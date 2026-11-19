// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: held payments and splice on arrival, on rust-lightning 0.3's
//! `htlc_interception_flags`.
//!
//! A phone is offline whenever its app isn't on screen, and a payment to a channel whose peer is
//! disconnected fails at once. With [`Config::hold_private_forwards`] the LSP sets
//! `ToOnlinePrivateChannels | ToOfflinePrivateChannels`, so every HTLC it forwards to a client's
//! private channel arrives as `Event::HTLCIntercepted`, whatever the payment type (a BOLT 11 route
//! hint, a BOLT 12 blinded path, keysend, an async payment released to the client). The channel
//! is found from the SCID the payer used, so no client needs an intercept SCID of its own. Each
//! intercepted HTLC:
//! - goes out at once when the client's channel is usable and can take it;
//! - is held while the client is offline (`on_held` wakes them) and goes out the moment they are
//!   back: on reconnect, on `ChannelReady` and on a splice locking (re-signalled as
//!   `ChannelReady`), with a slow timer as the fallback;
//! - is reported once through `on_short_of_room` when the client is online but their channel is
//!   too small for it; the LSP answers with [`crate::Node::set_held_payment_fee`] once it is
//!   adding room (a splice of its own coins), or [`crate::Node::refuse_held_payment`];
//! - is failed back after `hold_for`.
//!
//! r8 (`held_forwards.rs`) did the same on hold SCIDs only; this replaces them.
//!
//! [`Config::hold_private_forwards`]: crate::config::Config::hold_private_forwards

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::InterceptId;
use lightning::types::payment::PaymentHash;

use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::ChannelManager;

/// How long a payment for an offline client is held before it is failed back: inside a payer's
/// patience, and time enough for a push to wake the phone.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(50);

/// The fallback timer: a held payment goes out on events (reconnect, channel ready, splice
/// locked); this catches the deadline, and a channel that became usable without an event.
pub(crate) const FALLBACK_TICK: Duration = Duration::from_secs(5);

/// After a client reconnects, its channel becomes usable once it is reestablished, which LDK
/// signals with no event: the held payments for it are retried this often, this many times. Two
/// seconds is longer than any reestablish seen, and short of the fallback timer.
pub(crate) const RELEASE_RETRY_EVERY: Duration = Duration::from_millis(100);
pub(crate) const RELEASE_RETRIES: u32 = 20;

/// How many finished holds are kept for the admin console.
const RECENT: usize = 50;

/// Called with the client whose payment is being held because they are offline, once per
/// payment, to wake their device. It runs on the node's event handling: it must not block.
pub type OnHeld = Arc<dyn Fn(PublicKey) + Send + Sync>;

/// A held payment whose client is online, with a usable channel that is too small for it.
///
/// The LSP decides what to do, off this crate's threads, and answers with
/// [`crate::Node::set_held_payment_fee`] once the client agreed to the fee and a splice of its own
/// funds into the channel has started, or [`crate::Node::refuse_held_payment`]. Until then the
/// payment stays held, under its usual deadline. A multi-part payment is one of these per part,
/// all with the same `payment_hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortOfRoom {
	/// Names the part in the answer.
	pub intercept_id: InterceptId,
	/// The payment the part belongs to: the client's wallet agrees to a fee per payment hash.
	pub payment_hash: PaymentHash,
	/// The client the payment is for.
	pub customer: PublicKey,
	/// What the part carries for the client.
	pub amount_msat: u64,
	/// The most the client's channel can take right now.
	pub room_msat: u64,
}

/// Called once per held payment that is short of room (see [`ShortOfRoom`]). It runs on the
/// thread that processes held payments, so it must not block: hand the work to a thread of its
/// own.
pub type OnShortOfRoom = Arc<dyn Fn(ShortOfRoom) + Send + Sync>;

/// A payment that had to wait for its client, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldRecord {
	/// The client the payment was for.
	pub customer: PublicKey,
	/// What the client was to receive.
	pub amount_msat: u64,
	/// How long it was held.
	pub held_secs: u64,
	/// When it ended, in seconds since the Unix epoch.
	pub ended_at: u64,
	/// Forwarded once the client was back (or the room was there), or failed back.
	pub forwarded: bool,
	/// What we kept out of it: the fee for the room a splice on arrival added. Zero otherwise.
	pub fee_msat: u64,
	/// Why it was failed back before its deadline, when the LSP refused it.
	pub refused: Option<String>,
}

struct Held {
	intercept_id: InterceptId,
	payment_hash: PaymentHash,
	customer: PublicKey,
	amount_msat: u64,
	since: Instant,
	deadline: Instant,
	/// The client was offline, and `on_held` was told (once per payment).
	announced: bool,
	/// The LSP was asked about room for it (once per payment).
	room_asked: bool,
	/// Kept out of what is forwarded, once the LSP is adding room for it.
	fee_msat: u64,
}

pub(crate) struct HeldPayments {
	held: Mutex<Vec<Held>>,
	recent: Mutex<VecDeque<HoldRecord>>,
	hold_for: RwLock<Duration>,
	on_held: RwLock<Option<OnHeld>>,
	on_short_of_room: RwLock<Option<OnShortOfRoom>>,
	/// Clients that reconnected with something held for them, for the release task.
	reconnected: Mutex<HashSet<PublicKey>>,
	reconnect_notify: tokio::sync::Notify,
	channel_manager: Arc<ChannelManager>,
	logger: Arc<Logger>,
}

pub(crate) fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

impl HeldPayments {
	pub(crate) fn new(channel_manager: Arc<ChannelManager>, logger: Arc<Logger>) -> Self {
		Self {
			held: Mutex::new(Vec::new()),
			recent: Mutex::new(VecDeque::new()),
			hold_for: RwLock::new(DEFAULT_HOLD),
			on_held: RwLock::new(None),
			on_short_of_room: RwLock::new(None),
			reconnected: Mutex::new(HashSet::new()),
			reconnect_notify: tokio::sync::Notify::new(),
			channel_manager,
			logger,
		}
	}

	/// The client whose channel the payer asked for, when it is one of our channels. An intercept
	/// SCID (an LSPS2 just-in-time channel) is not one.
	pub(crate) fn customer_for(&self, requested_next_hop_scid: u64) -> Option<PublicKey> {
		self.channel_manager
			.list_channels()
			.into_iter()
			.find(|c| {
				c.short_channel_id == Some(requested_next_hop_scid)
					|| c.outbound_scid_alias == Some(requested_next_hop_scid)
					|| c.inbound_scid_alias == Some(requested_next_hop_scid)
			})
			.map(|c| c.counterparty.node_id)
	}

	pub(crate) fn set_hold_for(&self, hold_for: Duration) {
		*self.hold_for.write().expect("lock") = hold_for;
	}

	pub(crate) fn set_on_held(&self, on_held: OnHeld) {
		*self.on_held.write().expect("lock") = Some(on_held);
	}

	pub(crate) fn set_on_short_of_room(&self, on_short_of_room: OnShortOfRoom) {
		*self.on_short_of_room.write().expect("lock") = Some(on_short_of_room);
	}

	/// An HTLC for `customer` was intercepted: forward it now if it fits, otherwise hold it.
	pub(crate) fn intercepted(
		&self, intercept_id: InterceptId, payment_hash: PaymentHash, customer: PublicKey,
		amount_msat: u64,
	) {
		let since = Instant::now();
		let deadline = since + *self.hold_for.read().expect("lock");
		self.held.lock().expect("lock").push(Held {
			intercept_id,
			payment_hash,
			customer,
			amount_msat,
			since,
			deadline,
			announced: false,
			room_asked: false,
			fee_msat: 0,
		});
		self.release_for(customer);
	}

	/// The LSP is adding room for this held payment: forward it less `fee_msat` as soon as it
	/// fits. Returns the client, or `None` when the payment is no longer held.
	pub(crate) fn set_fee(&self, intercept_id: InterceptId, fee_msat: u64) -> Option<PublicKey> {
		let mut held = self.held.lock().expect("lock");
		let h = held.iter_mut().find(|h| h.intercept_id == intercept_id)?;
		h.fee_msat = fee_msat.min(h.amount_msat);
		Some(h.customer)
	}

	/// The LSP won't make room for this held payment: fail it back now rather than at its
	/// deadline. Returns whether it was still held.
	pub(crate) fn refuse(&self, intercept_id: InterceptId, reason: &str) -> bool {
		let h = {
			let mut held = self.held.lock().expect("lock");
			let Some(index) = held.iter().position(|h| h.intercept_id == intercept_id) else {
				return false;
			};
			held.remove(index)
		};
		if let Err(e) = self.channel_manager.fail_intercepted_htlc(h.intercept_id) {
			log_error!(self.logger, "Failed to fail back a refused payment: {:?}", e);
		}
		log_info!(
			self.logger,
			"Refused a payment of {} msat for customer {}: {}",
			h.amount_msat,
			h.customer,
			reason
		);
		self.record_ended(&h, false, Some(reason.to_string()));
		true
	}

	/// Payments held right now: `(customer, amount_msat, seconds left)`.
	pub(crate) fn held(&self) -> Vec<(PublicKey, u64, u64)> {
		let now = Instant::now();
		self.held
			.lock()
			.expect("lock")
			.iter()
			.map(|h| {
				(h.customer, h.amount_msat, h.deadline.saturating_duration_since(now).as_secs())
			})
			.collect()
	}

	/// Holds that ended, newest first.
	pub(crate) fn recent(&self) -> Vec<HoldRecord> {
		self.recent.lock().expect("lock").iter().cloned().collect()
	}

	fn record_ended(&self, h: &Held, forwarded: bool, refused: Option<String>) {
		let mut recent = self.recent.lock().expect("lock");
		recent.push_front(HoldRecord {
			customer: h.customer,
			amount_msat: h.amount_msat,
			held_secs: h.since.elapsed().as_secs(),
			ended_at: now_secs(),
			forwarded,
			fee_msat: if forwarded { h.fee_msat } else { 0 },
			refused,
		});
		recent.truncate(RECENT);
	}

	/// Whether anything is still held for this client.
	pub(crate) fn has_held(&self, peer: &PublicKey) -> bool {
		self.held.lock().expect("lock").iter().any(|h| &h.customer == peer)
	}

	/// A peer connected (called from the peer handler, so it only notes it): the release task
	/// retries its held payments while its channel is being reestablished.
	pub(crate) fn peer_connected(&self, peer: PublicKey) {
		if self.has_held(&peer) {
			self.reconnected.lock().expect("lock").insert(peer);
			self.reconnect_notify.notify_one();
		}
	}

	/// Waits until a client with something held reconnects, and returns those that did.
	pub(crate) async fn next_reconnected(&self) -> Vec<PublicKey> {
		loop {
			let peers: Vec<_> = self.reconnected.lock().expect("lock").drain().collect();
			if !peers.is_empty() {
				return peers;
			}
			self.reconnect_notify.notified().await;
		}
	}

	/// Forwards what can go now, fails back what has waited too long, and announces newly held
	/// payments. Runs on the fallback timer.
	pub(crate) fn process(&self) {
		self.process_for(None);
	}

	/// The same for one client: called the moment their channel may have become usable or big
	/// enough (reconnect, channel ready, splice locked, an answer from the LSP), so a held payment
	/// goes out then rather than a timer tick later.
	pub(crate) fn release_for(&self, peer: PublicKey) {
		self.process_for(Some(peer));
	}

	fn process_for(&self, only: Option<PublicKey>) {
		let now = Instant::now();
		let mut announce = Vec::new();
		let mut short_of_room = Vec::new();
		{
			let mut held = self.held.lock().expect("lock");
			let mut keep = Vec::with_capacity(held.len());
			for mut h in held.drain(..) {
				if only.is_some_and(|peer| h.customer != peer) {
					keep.push(h);
					continue;
				}
				// What goes to the client: all of it, or all but the fee for room added for it.
				let forward_msat = h.amount_msat - h.fee_msat;
				let channels = self.channel_manager.list_channels_with_counterparty(&h.customer);
				let channel = channels
					.iter()
					.filter(|c| c.is_usable && c.next_outbound_htlc_limit_msat >= forward_msat)
					.max_by_key(|c| c.next_outbound_htlc_limit_msat);
				if let Some(channel) = channel {
					match self.channel_manager.forward_intercepted_htlc(
						h.intercept_id,
						&channel.channel_id,
						h.customer,
						forward_msat,
					) {
						Ok(()) => {
							log_info!(
								self.logger,
								"Forwarded a payment of {} msat to customer {}{}{}",
								forward_msat,
								h.customer,
								if h.announced { " after holding it" } else { "" },
								if h.fee_msat > 0 {
									format!(", keeping {} msat for the room added", h.fee_msat)
								} else {
									String::new()
								}
							);
							if h.announced || h.room_asked {
								self.record_ended(&h, true, None);
							}
							continue;
						},
						Err(e) => {
							log_debug!(
								self.logger,
								"Couldn't forward to {} yet: {:?}",
								h.customer,
								e
							);
						},
					}
				}
				if now >= h.deadline {
					if let Err(e) = self.channel_manager.fail_intercepted_htlc(h.intercept_id) {
						log_error!(self.logger, "Failed to fail back a held payment: {:?}", e);
					}
					log_info!(
						self.logger,
						"Gave up on a held payment of {} msat for customer {}: not forwarded in time",
						h.amount_msat,
						h.customer
					);
					self.record_ended(&h, false, None);
					continue;
				}
				// Online, with a usable channel that is too small: the LSP decides about room, once
				// per payment. An offline client is woken first.
				let room_msat = channels
					.iter()
					.filter(|c| c.is_usable)
					.map(|c| c.next_outbound_htlc_limit_msat)
					.max();
				let deciding = self.on_short_of_room.read().expect("lock").is_some();
				if let (Some(room_msat), true) = (room_msat, deciding) {
					if !h.room_asked {
						h.room_asked = true;
						log_info!(
							self.logger,
							"A payment of {} msat for customer {} is larger than their room of {} msat",
							h.amount_msat,
							h.customer,
							room_msat
						);
						short_of_room.push(ShortOfRoom {
							intercept_id: h.intercept_id,
							payment_hash: h.payment_hash,
							customer: h.customer,
							amount_msat: h.amount_msat,
							room_msat,
						});
					}
				} else if room_msat.is_none() && !h.announced {
					h.announced = true;
					log_info!(
						self.logger,
						"Holding a payment of {} msat for customer {} until they're back",
						h.amount_msat,
						h.customer
					);
					announce.push(h.customer);
				}
				keep.push(h);
			}
			*held = keep;
		}
		// Outside the lock: the LSP's answer comes back through `set_fee` or `refuse`.
		if !short_of_room.is_empty() {
			if let Some(on_short_of_room) = self.on_short_of_room.read().expect("lock").clone() {
				for short in short_of_room {
					on_short_of_room(short);
				}
			}
		}
		// Outside the lock: waking the phone may reach out to the network.
		if !announce.is_empty() {
			if let Some(on_held) = self.on_held.read().expect("lock").clone() {
				for customer in announce {
					on_held(customer);
				}
			}
		}
	}
}
