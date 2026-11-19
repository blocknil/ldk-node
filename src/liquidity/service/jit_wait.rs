// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: a first payment waits for its offline client.
//!
//! Upstream fails a JIT channel's first payment back when the client isn't connected as it
//! arrives (the TODO in `LSPS2ServiceEvent::OpenChannel`). A phone is disconnected whenever its
//! app isn't on screen, so that is most first payments. Here the payment waits instead, at most
//! the wait set with [`crate::Node::set_hold_duration`]: the client is woken (the handler set with
//! [`crate::Node::set_payment_held_handler`]), and the channel opens once it connects. If the
//! client drops before the open completes, LDK discards the unfunded channel; the payment then
//! waits again, and the open restarts once LDK has released the funding's coins
//! (`DiscardFunding`) and the client is back.
//!
//! This module only keeps the bookkeeping; `LSPS2ServiceLiquiditySource` does the opening and
//! failing. Nothing here is persisted: after a restart the payment is failed back by
//! [`crate::Node::fail_stuck_jit_payments`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;

/// Called with the client a first payment waits for, so it can be woken. Blocknil patch.
///
/// The same shape as the held-payments wake callback, so one handler serves both. It is called on
/// the node's event handling: it must not block.
pub type OnJitWaiting = Arc<dyn Fn(PublicKey) + Send + Sync>;

/// How long a first payment waits for its client unless [`crate::Node::set_hold_duration`] says
/// otherwise. r8's held-payment default.
pub(crate) const DEFAULT_JIT_WAIT: Duration = Duration::from_secs(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
	/// The channel is being opened (or is about to be).
	Opening,
	/// The client isn't connected: the open waits for it.
	Waiting,
	/// The client dropped mid-open: the open waits for LDK to release the coins of the discarded
	/// channel's funding (`DiscardFunding` for this channel), then for the client.
	AwaitingDiscard(ChannelId),
}

#[derive(Clone, Debug)]
struct JitOpen {
	/// The `OpenChannel` event the open answers, handled again to retry it.
	open_channel: LSPS2ServiceEvent,
	client: PublicKey,
	amt_to_forward_msat: u64,
	deadline: Instant,
	state: State,
}

/// First payments whose JIT channel isn't open yet, by `user_channel_id`.
pub(crate) struct JitWaits {
	opens: Mutex<HashMap<u128, JitOpen>>,
	wait: RwLock<Duration>,
	on_waiting: RwLock<Option<OnJitWaiting>>,
}

impl JitWaits {
	pub(crate) fn new() -> Self {
		Self {
			opens: Mutex::new(HashMap::new()),
			wait: RwLock::new(DEFAULT_JIT_WAIT),
			on_waiting: RwLock::new(None),
		}
	}

	pub(crate) fn set_wait(&self, wait: Duration) {
		*self.wait.write().expect("lock") = wait;
	}

	pub(crate) fn set_on_waiting(&self, on_waiting: OnJitWaiting) {
		*self.on_waiting.write().expect("lock") = Some(on_waiting);
	}

	/// An `OpenChannel` event is being handled (first time, or retried): the open is under way.
	/// Returns whether it is the first time, i.e. whether a wait would be a new one.
	pub(crate) fn opening(&self, open_channel: LSPS2ServiceEvent, now: Instant) -> bool {
		let LSPS2ServiceEvent::OpenChannel {
			their_network_key: client,
			amt_to_forward_msat,
			user_channel_id,
			..
		} = open_channel
		else {
			debug_assert!(false, "only OpenChannel events are opens");
			return false;
		};
		let deadline = now + *self.wait.read().expect("lock");
		let mut opens = self.opens.lock().expect("lock");
		match opens.get_mut(&user_channel_id) {
			Some(open) => {
				open.state = State::Opening;
				false
			},
			None => {
				let state = State::Opening;
				let open = JitOpen { open_channel, client, amt_to_forward_msat, deadline, state };
				opens.insert(user_channel_id, open);
				true
			},
		}
	}

	/// The client isn't connected. Returns whether the payment waits for it: false once the
	/// deadline passed (or the wait is zero), when the caller fails it back as upstream does.
	pub(crate) fn wait_for_client(&self, user_channel_id: u128, now: Instant) -> bool {
		let mut opens = self.opens.lock().expect("lock");
		match opens.get_mut(&user_channel_id) {
			Some(open) if now < open.deadline => {
				open.state = State::Waiting;
				true
			},
			Some(_) => {
				opens.remove(&user_channel_id);
				false
			},
			None => false,
		}
	}

	/// Calls the wake handler for `client`, if one is set.
	pub(crate) fn wake(&self, client: PublicKey) {
		let on_waiting = self.on_waiting.read().expect("lock").clone();
		if let Some(on_waiting) = on_waiting {
			on_waiting(client);
		}
	}

	/// The channel of an open closed before it was ready. Returns whether the payment waits for
	/// the client again, which it does when the client disconnected mid-open and time is left. If
	/// a funding transaction had been made (`funding_generated`), the open restarts only after
	/// [`Self::funding_discarded`]. Otherwise the open is forgotten and the caller fails the
	/// payment back as upstream does.
	pub(crate) fn channel_closed(
		&self, user_channel_id: u128, channel_id: ChannelId, disconnected: bool,
		funding_generated: bool, now: Instant,
	) -> bool {
		let mut opens = self.opens.lock().expect("lock");
		match opens.get_mut(&user_channel_id) {
			Some(open) if open.state == State::Opening && disconnected && now < open.deadline => {
				open.state = if funding_generated {
					State::AwaitingDiscard(channel_id)
				} else {
					State::Waiting
				};
				true
			},
			Some(_) => {
				opens.remove(&user_channel_id);
				false
			},
			None => false,
		}
	}

	/// LDK released the funding of `channel_id`: an open waiting on it now waits for the client.
	pub(crate) fn funding_discarded(&self, channel_id: ChannelId) {
		for open in self.opens.lock().expect("lock").values_mut() {
			if open.state == State::AwaitingDiscard(channel_id) {
				open.state = State::Waiting;
			}
		}
	}

	/// The open is over (channel ready, or the payment failed back).
	pub(crate) fn remove(&self, user_channel_id: u128) {
		self.opens.lock().expect("lock").remove(&user_channel_id);
	}

	/// Takes what is due: the waiting opens whose client is connected, as the `OpenChannel` events
	/// to handle again (marked opening), and the waits past their deadline, as
	/// `(client, user_channel_id)` to fail back (forgotten). An open under way is never expired: it
	/// ends in a ready channel or a close.
	pub(crate) fn take_due(
		&self, now: Instant, is_connected: impl Fn(&PublicKey) -> bool,
	) -> (Vec<LSPS2ServiceEvent>, Vec<(PublicKey, u128)>) {
		let mut opens = self.opens.lock().expect("lock");
		let expired: Vec<u128> = opens
			.iter()
			.filter(|(_, open)| open.state != State::Opening && now >= open.deadline)
			.map(|(user_channel_id, _)| *user_channel_id)
			.collect();
		let expired = expired
			.into_iter()
			.filter_map(|id| opens.remove(&id).map(|open| (open.client, id)))
			.collect();
		let mut retry = Vec::new();
		for open in opens.values_mut() {
			if open.state == State::Waiting && is_connected(&open.client) {
				open.state = State::Opening;
				retry.push(open.open_channel.clone());
			}
		}
		(retry, expired)
	}

	/// The first payments waiting for their client: `(client, amount to forward in msat)`.
	pub(crate) fn waiting(&self) -> Vec<(PublicKey, u64)> {
		self.opens
			.lock()
			.expect("lock")
			.values()
			.filter(|open| open.state != State::Opening)
			.map(|open| (open.client, open.amt_to_forward_msat))
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	use super::*;

	fn client() -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap())
	}

	fn waits(wait: Duration) -> JitWaits {
		let waits = JitWaits::new();
		waits.set_wait(wait);
		waits
	}

	fn open_channel(id: u128) -> LSPS2ServiceEvent {
		LSPS2ServiceEvent::OpenChannel {
			their_network_key: client(),
			amt_to_forward_msat: 5_000_000,
			opening_fee_msat: 1_000,
			user_channel_id: id,
			intercept_scid: 42,
			max_client_to_self_delay: Some(144),
		}
	}

	fn open(waits: &JitWaits, id: u128, now: Instant) -> bool {
		waits.opening(open_channel(id), now)
	}

	#[test]
	fn an_offline_client_is_waited_for_and_the_open_retried_once_connected() {
		let now = Instant::now();
		let waits = waits(Duration::from_secs(50));
		assert!(open(&waits, 1, now));
		assert!(waits.wait_for_client(1, now));
		assert_eq!(waits.waiting(), vec![(client(), 5_000_000)]);

		// Not connected yet: nothing is due.
		let (retry, expired) = waits.take_due(now, |_| false);
		assert!(retry.is_empty() && expired.is_empty());

		// Connected: the same `OpenChannel` is handed back, once.
		let (retry, expired) = waits.take_due(now, |_| true);
		assert!(expired.is_empty());
		assert_eq!(retry, vec![open_channel(1)]);
		assert!(waits.take_due(now, |_| true).0.is_empty());
		// Handling it again is not a new wait (no second wake), and keeps the deadline.
		assert!(!open(&waits, 1, now + Duration::from_secs(10)));
		assert!(waits.wait_for_client(1, now + Duration::from_secs(49)));
		assert!(!waits.wait_for_client(1, now + Duration::from_secs(50)));
		assert!(waits.waiting().is_empty());
	}

	#[test]
	fn a_wait_past_its_deadline_is_failed_back_but_an_open_under_way_is_not() {
		let now = Instant::now();
		let waits = waits(Duration::from_secs(50));
		open(&waits, 1, now);
		waits.wait_for_client(1, now);
		open(&waits, 2, now);
		let later = now + Duration::from_secs(50);
		let (retry, expired) = waits.take_due(later, |_| false);
		assert!(retry.is_empty());
		assert_eq!(expired, vec![(client(), 1)]);
		assert!(waits.take_due(later, |_| false).1.is_empty());
	}

	#[test]
	fn no_wait_when_the_wait_is_zero() {
		let now = Instant::now();
		let waits = waits(Duration::ZERO);
		open(&waits, 1, now);
		assert!(!waits.wait_for_client(1, now));
		assert!(waits.waiting().is_empty());
	}

	#[test]
	fn a_client_dropping_mid_open_is_waited_for_again_after_the_funding_is_discarded() {
		let now = Instant::now();
		let waits = waits(Duration::from_secs(50));
		let channel_id = ChannelId([3; 32]);
		open(&waits, 1, now);
		// The client disconnected after the funding transaction was made.
		assert!(waits.channel_closed(1, channel_id, true, true, now));
		assert_eq!(waits.waiting(), vec![(client(), 5_000_000)]);
		// Its coins aren't released yet: no retry, even with the client back.
		assert!(waits.take_due(now, |_| true).0.is_empty());
		waits.funding_discarded(ChannelId([4; 32]));
		assert!(waits.take_due(now, |_| true).0.is_empty());
		waits.funding_discarded(channel_id);
		assert_eq!(waits.take_due(now, |_| true).0.len(), 1);

		// Dropped before any funding transaction: waits for the client straight away.
		open(&waits, 2, now);
		assert!(waits.channel_closed(2, ChannelId([5; 32]), true, false, now));
		assert_eq!(waits.take_due(now, |_| true).0.len(), 1);
	}

	#[test]
	fn other_closes_fail_the_payment_back() {
		let now = Instant::now();
		let waits = waits(Duration::from_secs(50));
		let channel_id = ChannelId([3; 32]);
		// The client refused the channel (not a disconnect).
		open(&waits, 1, now);
		assert!(!waits.channel_closed(1, channel_id, false, true, now));
		// Disconnected, but out of time.
		open(&waits, 2, now);
		assert!(!waits.channel_closed(2, channel_id, true, true, now + Duration::from_secs(50)));
		// Not an open we track.
		assert!(!waits.channel_closed(3, channel_id, true, true, now));
		assert!(waits.waiting().is_empty());
	}
}
