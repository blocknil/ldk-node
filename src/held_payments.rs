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
//! r8 (`held_forwards.rs`) did the same on hold SCIDs only: an intercept SCID per client, which
//! its wallet put in its invoices' route hints. They are no longer needed, but invoices phones
//! handed out before the upgrade carry them: the hold SCIDs r8 stored (`blocknil/hold_scids`) are
//! honoured for [`HOLD_SCID_LIFETIME`] after this code first saw them, and an HTLC on one is held
//! like any other for its client. After that it is failed back at once.
//!
//! [`Config::hold_private_forwards`]: crate::config::Config::hold_private_forwards

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::PublicKey;
use lightning::events::{HTLCHandlingFailureReason, HTLCHandlingFailureType};
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::onion_utils::LocalHTLCFailureReason;
use lightning::ln::types::ChannelId;
use lightning::types::payment::PaymentHash;
use lightning::util::persist::KVStore;

use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::{ChannelManager, DynStore};
use crate::Error;

/// Where r8 kept its hold SCIDs, and this code still does: one `scid customer first_seen` line per
/// SCID (hex, hex, decimal seconds since the Unix epoch). r8 wrote `scid customer` only.
const HOLD_SCIDS_NAMESPACE: &str = "blocknil";
const HOLD_SCIDS_KEY: &str = "hold_scids";

/// How long a hold SCID is honoured after this code first saw it: invoices handed out before the
/// upgrade, and by phones still on r8, keep working that long.
pub(crate) const HOLD_SCID_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);

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

/// Blocknil patch (decision 4): how long a forward is remembered, to name the payment if it fails
/// back because the client went offline before it reached their channel. rust-lightning adds a
/// forwarded HTLC to the channel on its next forwarding pass, a few tens of milliseconds later (2 s
/// after a start); this leaves ample room.
const FORWARD_RACE_WINDOW: Duration = Duration::from_secs(10);

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
	/// Forwarded once the client was back (or the room was there), or failed back. A forward the
	/// client went offline for before it reached their channel ends up failed back: `false`.
	pub forwarded: bool,
	/// What we kept out of it: the fee for the room a splice on arrival added. Zero otherwise.
	pub fee_msat: u64,
	/// Why it was failed back before its deadline: the LSP refused it, or the client went offline
	/// right after it was forwarded.
	pub refused: Option<String>,
	/// The payment it was part of.
	pub payment_hash: PaymentHash,
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
	/// It couldn't go out at once (it is recorded in `recent` when it ends).
	was_held: bool,
}

/// Blocknil patch (decision 4): an HTLC handed to rust-lightning with `forward_intercepted_htlc`,
/// not yet known to have reached the client's channel.
struct Forwarded {
	customer: PublicKey,
	channel_id: ChannelId,
	payment_hash: PaymentHash,
	amount_msat: u64,
	at: Instant,
}

/// Where an intercepted HTLC goes.
pub(crate) enum NextHop {
	/// To this client: one of our channels with them, or a hold SCID still honoured.
	Customer(PublicKey),
	/// A hold SCID of this client's, no longer honoured.
	LapsedHoldScid(PublicKey),
}

pub(crate) struct HeldPayments {
	held: Mutex<Vec<Held>>,
	/// Hold SCIDs: client, and when this code first saw the SCID.
	hold_scids: RwLock<HashMap<u64, (PublicKey, u64)>>,
	kv_store: Arc<DynStore>,
	ledger: ForwardLedger,
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

fn encode_hold_scids(scids: &HashMap<u64, (PublicKey, u64)>) -> Vec<u8> {
	let mut lines: Vec<_> = scids
		.iter()
		.map(|(scid, (customer, first_seen))| format!("{scid:016x} {customer} {first_seen}\n"))
		.collect();
	lines.sort();
	lines.concat().into_bytes()
}

/// Reads both formats; `None` for a line r8 wrote (no first-seen time yet).
fn decode_hold_scids(bytes: &[u8]) -> HashMap<u64, (PublicKey, Option<u64>)> {
	String::from_utf8_lossy(bytes)
		.lines()
		.filter_map(|line| {
			let mut fields = line.split(' ');
			let scid = u64::from_str_radix(fields.next()?, 16).ok()?;
			let customer = fields.next()?.parse().ok()?;
			let first_seen = match fields.next() {
				Some(secs) => Some(secs.parse().ok()?),
				None => None,
			};
			fields.next().is_none().then_some((scid, (customer, first_seen)))
		})
		.collect()
}

/// Blocknil patch (decision 4): the forward of ours that a failed HTLC was, taken out of
/// `forwarded`, when rust-lightning failed it back because the client was offline (`PeerOffline`)
/// as it came to add it to their channel. The latest one to that client's channel: a forward
/// fails on the forwarding pass right after it.
fn take_lost_forward(
	forwarded: &mut VecDeque<Forwarded>, failure_type: &HTLCHandlingFailureType,
	failure_reason: Option<&HTLCHandlingFailureReason>,
) -> Option<Forwarded> {
	let (
		HTLCHandlingFailureType::Forward { node_id: Some(customer), channel_id },
		Some(HTLCHandlingFailureReason::Local { reason: LocalHTLCFailureReason::PeerOffline }),
	) = (failure_type, failure_reason)
	else {
		return None;
	};
	let index = forwarded.iter().rposition(|f| {
		f.customer == *customer
			&& f.channel_id == *channel_id
			&& f.at.elapsed() <= FORWARD_RACE_WINDOW
	})?;
	forwarded.remove(index)
}

/// Blocknil patch (decision 4): the records of holds that ended, and of our recent forwards with
/// the count of those lost to a client going offline (see [`HeldPayments::forward_failed`]).
struct ForwardLedger {
	recent: Mutex<VecDeque<HoldRecord>>,
	/// Our recent forwards, for `forward_failed`.
	forwarded: Mutex<VecDeque<Forwarded>>,
	/// Forwards failed back because the client went offline between the forward and the HTLC
	/// being added to their channel, since this node started.
	forwards_failed_offline: AtomicU64,
}

impl ForwardLedger {
	fn new() -> Self {
		Self {
			recent: Mutex::new(VecDeque::new()),
			forwarded: Mutex::new(VecDeque::new()),
			forwards_failed_offline: AtomicU64::new(0),
		}
	}

	fn recent(&self) -> Vec<HoldRecord> {
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
			payment_hash: h.payment_hash,
		});
		recent.truncate(RECENT);
	}

	/// Forwards `h` with `forward` (rust-lightning's `forward_intercepted_htlc`), and if that
	/// worked, records the hold's end and remembers the forward.
	///
	/// All of it under the `forwarded` lock, which `forward_failed` takes first. That lock is what
	/// makes it correct: rust-lightning can fail the HTLC back on another thread as soon as
	/// `forward` has handed it over, and `forward_failed` then waits until the forward and its
	/// record are both booked, so it finds the forward and has its record to correct. Without the
	/// lock, a failure handled in between went uncounted, or found no record and left one saying
	/// `forwarded`, with a fee, for a payment the client never got. The order inside the lock (the
	/// record, then the forward) doesn't matter for that.
	fn forward<E>(
		&self, h: &Held, channel_id: ChannelId, amount_msat: u64,
		forward: impl FnOnce() -> Result<(), E>,
	) -> Result<(), E> {
		let mut forwarded = self.forwarded.lock().expect("lock");
		forward()?;
		if h.was_held {
			self.record_ended(h, true, None);
		}
		while matches!(forwarded.front(), Some(f) if f.at.elapsed() > FORWARD_RACE_WINDOW) {
			forwarded.pop_front();
		}
		forwarded.push_back(Forwarded {
			customer: h.customer,
			channel_id,
			payment_hash: h.payment_hash,
			amount_msat,
			at: Instant::now(),
		});
		Ok(())
	}

	/// The forward of ours that a failed HTLC was, if rust-lightning failed it back because the
	/// client went offline, with the count of those since start. Its record, if it has one, now
	/// says it was failed back and kept no fee.
	fn forward_failed(
		&self, failure_type: &HTLCHandlingFailureType,
		failure_reason: Option<&HTLCHandlingFailureReason>,
	) -> Option<(Forwarded, u64)> {
		let mut forwarded = self.forwarded.lock().expect("lock");
		let lost = take_lost_forward(&mut forwarded, failure_type, failure_reason)?;
		drop(forwarded);
		// The admin console reads these records: a forward lost this way was failed back, not
		// delivered, and we kept no fee. Corrected before it is counted, so whoever sees the count
		// sees the record corrected (`Release` here, `Acquire` in `forwards_failed_offline`).
		{
			let mut recent = self.recent.lock().expect("lock");
			if let Some(record) = recent.iter_mut().find(|r| {
				r.forwarded && r.customer == lost.customer && r.payment_hash == lost.payment_hash
			}) {
				record.forwarded = false;
				record.fee_msat = 0;
				record.refused = Some(
					"failed back: the client went offline right after it was forwarded".to_string(),
				);
			}
		}
		let count = self.forwards_failed_offline.fetch_add(1, Ordering::Release) + 1;
		Some((lost, count))
	}

	fn forwards_failed_offline(&self) -> u64 {
		self.forwards_failed_offline.load(Ordering::Acquire)
	}
}

impl HeldPayments {
	pub(crate) fn new(
		channel_manager: Arc<ChannelManager>, kv_store: Arc<DynStore>, logger: Arc<Logger>,
	) -> Self {
		Self {
			held: Mutex::new(Vec::new()),
			hold_scids: RwLock::new(HashMap::new()),
			kv_store,
			ledger: ForwardLedger::new(),
			hold_for: RwLock::new(DEFAULT_HOLD),
			on_held: RwLock::new(None),
			on_short_of_room: RwLock::new(None),
			reconnected: Mutex::new(HashSet::new()),
			reconnect_notify: tokio::sync::Notify::new(),
			channel_manager,
			logger,
		}
	}

	/// Where an HTLC for `requested_next_hop_scid` goes: to the client of one of our channels, or
	/// of a hold SCID. `None` for anything else (an LSPS2 intercept SCID).
	pub(crate) fn next_hop(&self, requested_next_hop_scid: u64) -> Option<NextHop> {
		let channel = self.channel_manager.list_channels().into_iter().find(|c| {
			c.short_channel_id == Some(requested_next_hop_scid)
				|| c.outbound_scid_alias == Some(requested_next_hop_scid)
				|| c.inbound_scid_alias == Some(requested_next_hop_scid)
		});
		if let Some(channel) = channel {
			return Some(NextHop::Customer(channel.counterparty.node_id));
		}
		let (customer, first_seen) =
			*self.hold_scids.read().expect("lock").get(&requested_next_hop_scid)?;
		if now_secs() < first_seen.saturating_add(HOLD_SCID_LIFETIME.as_secs()) {
			Some(NextHop::Customer(customer))
		} else {
			Some(NextHop::LapsedHoldScid(customer))
		}
	}

	/// Reads the hold SCIDs at build. One written by r8 gets its first-seen time now, saved.
	pub(crate) async fn load_hold_scids(&self) -> Result<(), Error> {
		let bytes =
			match KVStore::read(&*self.kv_store, HOLD_SCIDS_NAMESPACE, "", HOLD_SCIDS_KEY).await {
				Ok(bytes) => bytes,
				Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => return Ok(()),
				Err(e) => {
					log_error!(self.logger, "Failed to read hold SCIDs: {}", e);
					return Err(Error::PersistenceFailed);
				},
			};
		let now = now_secs();
		let decoded = decode_hold_scids(&bytes);
		let first_seen_now = decoded.values().any(|(_, first_seen)| first_seen.is_none());
		let scids: HashMap<_, _> = decoded
			.into_iter()
			.map(|(scid, (customer, first_seen))| (scid, (customer, first_seen.unwrap_or(now))))
			.collect();
		log_info!(self.logger, "Honouring {} hold SCID(s) of earlier invoices", scids.len());
		if first_seen_now {
			self.save_hold_scids(&scids).await?;
		}
		*self.hold_scids.write().expect("lock") = scids;
		Ok(())
	}

	async fn save_hold_scids(&self, scids: &HashMap<u64, (PublicKey, u64)>) -> Result<(), Error> {
		KVStore::write(
			&*self.kv_store,
			HOLD_SCIDS_NAMESPACE,
			"",
			HOLD_SCIDS_KEY,
			encode_hold_scids(scids),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Failed to save hold SCIDs: {}", e);
			Error::PersistenceFailed
		})
	}

	/// The client's hold SCID, for a wallet still on r8 that asks for one: theirs while it is
	/// honoured, a new one (honoured from now) when they have none, an error once theirs lapsed.
	pub(crate) async fn hold_scid_for(
		&self, customer: PublicKey, new_scid: impl FnOnce() -> u64,
	) -> Result<u64, Error> {
		let existing = {
			let scids = self.hold_scids.read().expect("lock");
			scids.iter().find(|(_, (c, _))| *c == customer).map(|(scid, (_, s))| (*scid, *s))
		};
		if let Some((scid, first_seen)) = existing {
			if now_secs() < first_seen.saturating_add(HOLD_SCID_LIFETIME.as_secs()) {
				return Ok(scid);
			}
			log_info!(self.logger, "The hold SCID of customer {} lapsed", customer);
			return Err(Error::InvalidChannelId);
		}
		let scid = new_scid();
		let scids = {
			let mut scids = self.hold_scids.write().expect("lock");
			scids.insert(scid, (customer, now_secs()));
			scids.clone()
		};
		self.save_hold_scids(&scids).await?;
		log_info!(self.logger, "Hold SCID {} for customer {}", scid, customer);
		Ok(scid)
	}

	pub(crate) fn set_hold_for(&self, hold_for: Duration) {
		*self.hold_for.write().expect("lock") = hold_for;
	}

	/// Payments already held are announced to a handler set late: rust-lightning hands
	/// intercepted HTLCs back as the node starts, possibly before the application sets it.
	pub(crate) fn set_on_held(&self, on_held: OnHeld) {
		*self.on_held.write().expect("lock") = Some(on_held);
		self.process();
	}

	/// The same as `set_on_held`: payments already held are reported to a handler set late.
	pub(crate) fn set_on_short_of_room(&self, on_short_of_room: OnShortOfRoom) {
		*self.on_short_of_room.write().expect("lock") = Some(on_short_of_room);
		self.process();
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
			was_held: false,
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
		self.ledger.recent()
	}

	fn record_ended(&self, h: &Held, forwarded: bool, refused: Option<String>) {
		self.ledger.record_ended(h, forwarded, refused);
	}

	/// Blocknil patch (decision 4): an HTLC failed (`Event::HTLCHandlingFailed`). If it is one of
	/// our forwards that rust-lightning failed back because the client was offline when it came to
	/// add it to their channel (they dropped between our forward and that), it is logged and
	/// counted: rust-lightning 0.3 can't hand it back to us to hold again (rl-19 isn't ported), and
	/// the count shows how often that happens.
	pub(crate) fn forward_failed(
		&self, failure_type: &HTLCHandlingFailureType,
		failure_reason: Option<&HTLCHandlingFailureReason>,
	) {
		let Some((lost, count)) = self.ledger.forward_failed(failure_type, failure_reason) else {
			return;
		};
		log_info!(
			self.logger,
			"A payment of {} msat for customer {} (payment hash {}) failed back: they went offline \
			 after it was forwarded, before it reached their channel ({} since start)",
			lost.amount_msat,
			lost.customer,
			lost.payment_hash,
			count
		);
	}

	/// Blocknil patch (decision 4): see `forward_failed`.
	pub(crate) fn forwards_failed_offline(&self) -> u64 {
		self.ledger.forwards_failed_offline()
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
					match self.ledger.forward(&h, channel.channel_id, forward_msat, || {
						self.channel_manager.forward_intercepted_htlc(
							h.intercept_id,
							&channel.channel_id,
							h.customer,
							forward_msat,
						)
					}) {
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
				// Announced only to a handler: one set later still gets it (`set_on_held`).
				let waking = self.on_held.read().expect("lock").is_some();
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
				} else if room_msat.is_none() && !h.announced && waking {
					h.announced = true;
					log_info!(
						self.logger,
						"Holding a payment of {} msat for customer {} until they're back",
						h.amount_msat,
						h.customer
					);
					announce.push(h.customer);
				}
				h.was_held = true;
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_forward_failed_back_as_its_client_went_offline_is_found() {
		let customer: PublicKey =
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		let other: PublicKey =
			"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".parse().unwrap();
		let channel_id = ChannelId([1; 32]);
		let forward = |customer, payment_hash: u8, at| Forwarded {
			customer,
			channel_id,
			payment_hash: PaymentHash([payment_hash; 32]),
			amount_msat: 1_000 * payment_hash as u64,
			at,
		};
		let now = Instant::now();
		let mut forwarded = VecDeque::from([
			forward(customer, 1, now - FORWARD_RACE_WINDOW - Duration::from_secs(1)),
			forward(customer, 2, now),
			forward(customer, 3, now),
			forward(other, 4, now),
		]);
		let to = |node_id, channel_id| HTLCHandlingFailureType::Forward { node_id, channel_id };
		let local = |reason| Some(HTLCHandlingFailureReason::Local { reason });
		let offline = local(LocalHTLCFailureReason::PeerOffline);

		// Failed for another reason, by the client, or to another channel: not the race.
		let not_the_race = [
			(
				to(Some(customer), channel_id),
				local(LocalHTLCFailureReason::TemporaryChannelFailure),
			),
			(to(Some(customer), channel_id), Some(HTLCHandlingFailureReason::Downstream)),
			(to(Some(customer), channel_id), None),
			(to(Some(customer), ChannelId([2; 32])), offline.clone()),
			(to(None, channel_id), offline.clone()),
			(
				HTLCHandlingFailureType::InvalidForward { requested_forward_scid: 42 },
				offline.clone(),
			),
		];
		for (failure_type, reason) in &not_the_race {
			assert!(take_lost_forward(&mut forwarded, failure_type, reason.as_ref()).is_none());
		}
		assert_eq!(forwarded.len(), 4);

		// The race: the client's latest forward to that channel, once; never one too old.
		let race = to(Some(customer), channel_id);
		let lost = take_lost_forward(&mut forwarded, &race, offline.as_ref()).unwrap();
		assert_eq!(
			(lost.customer, lost.payment_hash, lost.amount_msat),
			(customer, PaymentHash([3; 32]), 3_000)
		);
		let lost = take_lost_forward(&mut forwarded, &race, offline.as_ref()).unwrap();
		assert_eq!(lost.payment_hash, PaymentHash([2; 32]));
		assert!(take_lost_forward(&mut forwarded, &race, offline.as_ref()).is_none());
		assert_eq!(forwarded.len(), 2, "the old one and the other client's are left");
	}

	/// The race of decision 4, with the failure handled while our forward is still being booked:
	/// rust-lightning fails the HTLC back on its forwarding pass, on another thread, as soon as the
	/// client is gone, and that can come before we have remembered the forward or written the
	/// hold's record. The failure must still be counted, and the record must say it was failed
	/// back with no fee: a record left saying `forwarded` shows the admin console a payment
	/// delivered, with a fee kept, that the client never got.
	///
	/// It fails if `ForwardLedger::forward` takes the `forwarded` lock after `forward()` rather
	/// than before (checked by mutation; that was the code before ldk3-held-record-order): the
	/// failure then runs before the forward is remembered, finds nothing, and goes uncounted.
	#[test]
	fn a_forward_failed_back_before_it_is_booked_is_counted_and_recorded_as_failed() {
		let customer: PublicKey =
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		let channel_id = ChannelId([1; 32]);
		let now = Instant::now();
		let held = Held {
			intercept_id: InterceptId([7; 32]),
			payment_hash: PaymentHash([9; 32]),
			customer,
			amount_msat: 150_000_000,
			since: now,
			deadline: now + Duration::from_secs(60),
			announced: true,
			room_asked: true,
			fee_msat: 110_000_000,
			was_held: true,
		};
		let ledger = Arc::new(ForwardLedger::new());
		let failure_type = HTLCHandlingFailureType::Forward { node_id: Some(customer), channel_id };
		let failure_reason =
			HTLCHandlingFailureReason::Local { reason: LocalHTLCFailureReason::PeerOffline };

		let failure = Mutex::new(None);
		ledger
			.forward(&held, channel_id, held.amount_msat - held.fee_msat, || {
				// The forward is with rust-lightning: the failure comes now, on its own thread.
				let (ledger, failure_type, failure_reason) =
					(Arc::clone(&ledger), failure_type.clone(), failure_reason.clone());
				let (done_tx, done_rx) = std::sync::mpsc::channel();
				*failure.lock().unwrap() = Some(std::thread::spawn(move || {
					let lost = ledger.forward_failed(&failure_type, Some(&failure_reason));
					let _ = done_tx.send(());
					lost
				}));
				// Give it the time to run before the forward returns, as a forwarding pass can.
				let _ = done_rx.recv_timeout(Duration::from_millis(300));
				Ok::<(), ()>(())
			})
			.unwrap();
		let lost = failure.lock().unwrap().take().unwrap().join().unwrap();

		let (lost, count) =
			lost.expect("the failure is our forward, lost to the client going away");
		assert_eq!((lost.payment_hash, count), (held.payment_hash, 1));
		assert_eq!(ledger.forwards_failed_offline(), 1);
		let records = ledger.recent();
		assert_eq!(records.len(), 1);
		let record = &records[0];
		assert!(!record.forwarded, "{record:?}");
		assert_eq!(record.fee_msat, 0, "{record:?}");
		assert!(
			record.refused.as_deref().is_some_and(|why| why.contains("went offline")),
			"{record:?}"
		);
	}

	#[test]
	fn hold_scids_read_r8s_format_and_keep_their_first_seen_time() {
		let customer: PublicKey =
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		// What r8 wrote (held_forwards.rs `encode`): `{scid:016x} {customer}` per line.
		let r8 =
			format!("{:016x} {}\n{:016x} {}\n", 0x0123_4567_89ab_cdef_u64, customer, 42, customer);
		let decoded = decode_hold_scids(r8.as_bytes());
		assert_eq!(decoded.len(), 2);
		assert_eq!(decoded[&0x0123_4567_89ab_cdef], (customer, None));
		assert_eq!(decoded[&42], (customer, None));

		let mut scids = HashMap::new();
		scids.insert(0x0123_4567_89ab_cdef_u64, (customer, 1_790_000_000));
		scids.insert(42, (customer, 7));
		let decoded = decode_hold_scids(&encode_hold_scids(&scids));
		let roundtrip: HashMap<_, _> =
			decoded.into_iter().map(|(scid, (c, s))| (scid, (c, s.unwrap()))).collect();
		assert_eq!(roundtrip, scids);

		assert!(decode_hold_scids(b"garbage\nzz 02 1\n").is_empty());
		let extra = format!("{:016x} {} 1 2\n{:016x} {} x\n", 1, customer, 2, customer);
		assert!(decode_hold_scids(extra.as_bytes()).is_empty());
	}
}
