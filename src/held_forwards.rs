// Blocknil patch: hold a payment for a customer whose phone is offline, instead of failing it.
//
// A payment to a channel whose peer is disconnected fails at once (`ChannelDisabled`), and a
// phone is disconnected whenever its app isn't on screen. LDK can only hold a payment that
// arrives on an intercept SCID, so each customer gets one (`scid_for`, kept in the store so
// invoices stay valid across restarts) and puts it in its invoices' route hints. A payment on it
// is forwarded at once when the customer's channel is usable; otherwise it is held, the
// `on_held` callback is told (to wake the customer's device), and it goes through as
// soon as the customer is back, or is failed back after `hold_for`.
//
// Onion messages held for an offline customer (a BOLT12 invoice request) get the same care: LDK
// hands them over the moment the customer connects, before their channel is reestablished, and a
// phone that answers then has no route to put in its invoice (`MissingPaths`). They wait here
// until the customer's channel is usable, or `ONION_WAIT` at most.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::msgs::OnionMessage;
use lightning::util::persist::KVStoreSync;

use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::{ChannelManager, DynStore, OnionMessenger};
use crate::Error;

const NAMESPACE: &str = "blocknil";
const SCIDS_KEY: &str = "hold_scids";

/// How long a payment for an offline customer is held before it is failed back: inside a
/// payer's patience, and time enough for a push to wake the phone.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(50);

/// Called with the customer whose payment is being held, once per payment.
pub type OnHeld = Arc<dyn Fn(PublicKey) + Send + Sync>;

/// A held payment whose customer is online, with a usable channel that is too small for it.
///
/// Blocknil patch (splice on arrival): the provider decides what to do, off this crate's threads,
/// and answers with [`crate::Node::set_held_payment_fee`] once it has started a splice of its own
/// funds into the channel, or [`crate::Node::refuse_held_payment`]. Until then the payment stays
/// held, under its usual deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortOfRoom {
	/// Names the payment in the answer.
	pub intercept_id: InterceptId,
	/// The customer the payment is for.
	pub customer: PublicKey,
	/// What the payment carries for the customer.
	pub amount_msat: u64,
	/// The most the customer's channel can take right now.
	pub room_msat: u64,
}

/// Called once per held payment that is short of room (see [`ShortOfRoom`]). It runs on the
/// thread that processes held payments, so it must not block: hand the work to a thread of its
/// own.
pub type OnShortOfRoom = Arc<dyn Fn(ShortOfRoom) + Send + Sync>;

/// The most our provider may keep out of a payment it forwards to us, for room it spliced into our
/// channel when the payment arrived (Blocknil patch: splice on arrival, the client side).
///
/// A payment that arrived only over channels with `provider` may carry a withheld fee of up to
/// `max_fee_ppm` of what the payer sent, or `min_fee_msat` when that is larger. Anything above is
/// refused, as is any withheld fee on a payment that came over another peer's channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFeeLimit {
	/// Our provider: the only peer allowed to withhold a fee outside a just-in-time channel open.
	pub provider: PublicKey,
	/// Parts per million of what the payer sent.
	pub max_fee_ppm: u32,
	/// A floor for small payments.
	pub min_fee_msat: u64,
}

/// The longest a reconnected customer's onion messages wait for their channel to come back.
const ONION_WAIT: Duration = Duration::from_secs(10);

/// How many finished holds are kept for the admin console.
const RECENT: usize = 50;

/// A payment that had to wait for its customer, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldRecord {
	/// The customer the payment was for.
	pub customer: PublicKey,
	/// What the customer was to receive.
	pub amount_msat: u64,
	/// How long it was held.
	pub held_secs: u64,
	/// When it ended, in seconds since the Unix epoch.
	pub ended_at: u64,
	/// Forwarded once the customer was back, or failed back after the hold ran out.
	pub forwarded: bool,
	/// What we kept out of it: the fee for the room a splice on arrival added. Zero otherwise.
	pub fee_msat: u64,
	/// Why it was failed back before its deadline, when the provider refused it.
	pub refused: Option<String>,
}

struct Held {
	intercept_id: InterceptId,
	customer: PublicKey,
	amount_msat: u64,
	since: Instant,
	deadline: Instant,
	announced: bool,
	/// The provider was asked about room for it (once per payment).
	room_asked: bool,
	/// Kept out of what is forwarded, once the provider spliced room in for it.
	fee_msat: u64,
}

pub(crate) struct HeldForwards {
	scids: RwLock<HashMap<u64, PublicKey>>,
	held: Mutex<Vec<Held>>,
	recent: Mutex<VecDeque<HoldRecord>>,
	onions: Mutex<Vec<(PublicKey, Vec<OnionMessage>, Instant)>>,
	hold_for: RwLock<Duration>,
	on_held: RwLock<Option<OnHeld>>,
	on_short_of_room: RwLock<Option<OnShortOfRoom>>,
	provider_fee_limit: RwLock<Option<ProviderFeeLimit>>,
	kv_store: Arc<DynStore>,
	channel_manager: Arc<ChannelManager>,
	onion_messenger: Arc<OnionMessenger>,
	logger: Arc<Logger>,
}

/// One `scid customer` pair per line, both hex: small, and readable when looking at the store.
fn encode(scids: &HashMap<u64, PublicKey>) -> Vec<u8> {
	let mut out = String::new();
	for (scid, customer) in scids {
		out.push_str(&format!("{scid:016x} {customer}\n"));
	}
	out.into_bytes()
}

fn decode(bytes: &[u8]) -> HashMap<u64, PublicKey> {
	String::from_utf8_lossy(bytes)
		.lines()
		.filter_map(|line| {
			let (scid, customer) = line.split_once(' ')?;
			Some((u64::from_str_radix(scid, 16).ok()?, customer.parse().ok()?))
		})
		.collect()
}

impl HeldForwards {
	pub(crate) fn new(
		kv_store: Arc<DynStore>, channel_manager: Arc<ChannelManager>,
		onion_messenger: Arc<OnionMessenger>, logger: Arc<Logger>,
	) -> Self {
		let scids = KVStoreSync::read(&*kv_store, NAMESPACE, "", SCIDS_KEY)
			.map(|bytes| decode(&bytes))
			.unwrap_or_default();
		Self {
			scids: RwLock::new(scids),
			held: Mutex::new(Vec::new()),
			recent: Mutex::new(VecDeque::new()),
			onions: Mutex::new(Vec::new()),
			hold_for: RwLock::new(DEFAULT_HOLD),
			on_held: RwLock::new(None),
			on_short_of_room: RwLock::new(None),
			provider_fee_limit: RwLock::new(None),
			kv_store,
			channel_manager,
			onion_messenger,
			logger,
		}
	}

	/// The customer's intercept SCID, made and saved the first time it is asked for.
	pub(crate) fn scid_for(&self, customer: PublicKey) -> Result<u64, Error> {
		let find = |scids: &HashMap<u64, PublicKey>| {
			scids.iter().find(|(_, c)| **c == customer).map(|(scid, _)| *scid)
		};
		if let Some(scid) = find(&self.scids.read().unwrap()) {
			return Ok(scid);
		}
		let mut scids = self.scids.write().unwrap();
		if let Some(scid) = find(&scids) {
			return Ok(scid);
		}
		let scid = self.channel_manager.get_intercept_scid();
		scids.insert(scid, customer);
		KVStoreSync::write(&*self.kv_store, NAMESPACE, "", SCIDS_KEY, encode(&scids)).map_err(|e| {
			log_error!(self.logger, "Failed to save hold SCIDs: {}", e);
			Error::PersistenceFailed
		})?;
		log_info!(self.logger, "Hold SCID {} for customer {}", scid, customer);
		Ok(scid)
	}

	pub(crate) fn is_hold_scid(&self, scid: u64) -> bool {
		self.scids.read().unwrap().contains_key(&scid)
	}

	pub(crate) fn set_hold_for(&self, hold_for: Duration) {
		*self.hold_for.write().unwrap() = hold_for;
	}

	pub(crate) fn set_on_held(&self, on_held: OnHeld) {
		*self.on_held.write().unwrap() = Some(on_held);
	}

	pub(crate) fn set_on_short_of_room(&self, on_short_of_room: OnShortOfRoom) {
		*self.on_short_of_room.write().unwrap() = Some(on_short_of_room);
	}

	/// Client side: accept fees withheld by our provider up to `limit`, and have our channels with
	/// it accept payments that carry less than the payer sent (LDK's `accept_underpaying_htlcs`).
	pub(crate) fn set_provider_fee_limit(&self, limit: Option<ProviderFeeLimit>) {
		*self.provider_fee_limit.write().unwrap() = limit;
		if let Some(limit) = limit {
			self.allow_underpaying_from(&limit.provider);
		}
	}

	/// Sets `accept_underpaying_htlcs` on our channels with `peer`, when it is our provider. Called
	/// when the limit is set and whenever one of our channels becomes ready.
	pub(crate) fn allow_underpaying_from(&self, peer: &PublicKey) {
		let Some(limit) = *self.provider_fee_limit.read().unwrap() else { return };
		if &limit.provider != peer {
			return;
		}
		let channel_ids: Vec<_> = self
			.channel_manager
			.list_channels_with_counterparty(peer)
			.into_iter()
			.filter(|c| !c.config.is_some_and(|config| config.accept_underpaying_htlcs))
			.map(|c| c.channel_id)
			.collect();
		if channel_ids.is_empty() {
			return;
		}
		let update = lightning::util::config::ChannelConfigUpdate {
			accept_underpaying_htlcs: Some(true),
			..Default::default()
		};
		if let Err(e) =
			self.channel_manager.update_partial_channel_config(peer, &channel_ids, &update)
		{
			log_error!(self.logger, "Failed to let our provider's channels carry its fee: {:?}", e);
		}
	}

	/// Client side: the most our provider may withhold from a payment of `sent_msat` (what the payer
	/// sent) that arrived over `receiving_channel_ids`: zero unless every one of them is a channel
	/// with our provider and a limit is set.
	pub(crate) fn provider_fee_allowance(
		&self, receiving_channel_ids: &[(lightning::ln::types::ChannelId, Option<u128>)],
		sent_msat: u64,
	) -> u64 {
		let Some(limit) = *self.provider_fee_limit.read().unwrap() else { return 0 };
		if receiving_channel_ids.is_empty() {
			return 0;
		}
		let channels = self.channel_manager.list_channels_with_counterparty(&limit.provider);
		let all_from_provider = receiving_channel_ids
			.iter()
			.all(|(id, _)| channels.iter().any(|c| &c.channel_id == id));
		if !all_from_provider {
			return 0;
		}
		let proportional = sent_msat.saturating_mul(limit.max_fee_ppm as u64) / 1_000_000;
		proportional.max(limit.min_fee_msat)
	}

	/// The provider spliced room in for this held payment: forward it less `fee_msat` as soon as it
	/// fits. Returns the customer, or `None` when the payment is no longer held.
	pub(crate) fn set_fee(&self, intercept_id: InterceptId, fee_msat: u64) -> Option<PublicKey> {
		let mut held = self.held.lock().unwrap();
		let h = held.iter_mut().find(|h| h.intercept_id == intercept_id)?;
		h.fee_msat = fee_msat.min(h.amount_msat);
		Some(h.customer)
	}

	/// The provider won't make room for this held payment: fail it back now rather than at its
	/// deadline. Returns whether it was still held.
	pub(crate) fn refuse(&self, intercept_id: InterceptId, reason: &str) -> bool {
		let h = {
			let mut held = self.held.lock().unwrap();
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
			.unwrap()
			.iter()
			.map(|h| (h.customer, h.amount_msat, h.deadline.saturating_duration_since(now).as_secs()))
			.collect()
	}

	/// Holds that ended, newest first.
	pub(crate) fn recent(&self) -> Vec<HoldRecord> {
		self.recent.lock().unwrap().iter().cloned().collect()
	}

	fn record(&self, h: &Held, forwarded: bool) {
		self.record_ended(h, forwarded, None);
	}

	fn record_ended(&self, h: &Held, forwarded: bool, refused: Option<String>) {
		let ended_at =
			SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default();
		let mut recent = self.recent.lock().unwrap();
		recent.push_front(HoldRecord {
			customer: h.customer,
			amount_msat: h.amount_msat,
			held_secs: h.since.elapsed().as_secs(),
			ended_at,
			forwarded,
			fee_msat: if forwarded { h.fee_msat } else { 0 },
			refused,
		});
		recent.truncate(RECENT);
	}

	/// Whether the peer is ready to answer an onion message: it has a usable channel with us, or
	/// none that could become usable (no channel at all, or only ones still opening).
	fn ready_for_onions(&self, peer: &PublicKey) -> bool {
		let channels = self.channel_manager.list_channels_with_counterparty(peer);
		channels.iter().any(|c| c.is_usable) || !channels.iter().any(|c| c.is_channel_ready)
	}

	/// Whether a peer whose onion message arrived must be woken: it has a channel with us that
	/// isn't usable yet, so the message waits for it (`release_onion_messages`). Blocknil patch.
	pub(crate) fn needs_wake_for_onions(&self, peer: &PublicKey) -> bool {
		!self.ready_for_onions(peer)
	}

	fn forward_onions(&self, peer: &PublicKey, messages: Vec<OnionMessage>) {
		for message in messages {
			if let Err(e) = self.onion_messenger.forward_onion_message(message, peer) {
				log_debug!(self.logger, "Failed to forward an onion message to {}: {:?}", peer, e);
			}
		}
	}

	/// A peer whose onion messages were held came back: forward them once its channel is usable.
	pub(crate) fn release_onion_messages(&self, peer: PublicKey, messages: Vec<OnionMessage>) {
		if messages.is_empty() {
			return;
		}
		if self.ready_for_onions(&peer) {
			self.forward_onions(&peer, messages);
			return;
		}
		log_info!(
			self.logger,
			"Holding {} onion message(s) for {} until their channel is back",
			messages.len(),
			peer
		);
		self.onions.lock().unwrap().push((peer, messages, Instant::now() + ONION_WAIT));
	}

	fn process_onions(&self) {
		let now = Instant::now();
		let due: Vec<(PublicKey, Vec<OnionMessage>)> = {
			let mut onions = self.onions.lock().unwrap();
			let (due, keep): (Vec<_>, Vec<_>) = onions
				.drain(..)
				.partition(|(peer, _, deadline)| now >= *deadline || self.ready_for_onions(peer));
			*onions = keep;
			due.into_iter().map(|(peer, messages, _)| (peer, messages)).collect()
		};
		for (peer, messages) in due {
			log_debug!(self.logger, "Releasing {} onion message(s) to {}", messages.len(), peer);
			self.forward_onions(&peer, messages);
		}
	}

	/// An HTLC arrived on one of our hold SCIDs.
	pub(crate) fn intercepted(&self, scid: u64, intercept_id: InterceptId, amount_msat: u64) {
		let Some(customer) = self.scids.read().unwrap().get(&scid).copied() else { return };
		let since = Instant::now();
		let deadline = since + *self.hold_for.read().unwrap();
		self.held.lock().unwrap().push(Held {
			intercept_id,
			customer,
			amount_msat,
			since,
			deadline,
			announced: false,
			room_asked: false,
			fee_msat: 0,
		});
		self.process();
	}

	/// Forwards what can go now, fails back what has waited too long, and announces newly held
	/// payments. Runs on every interception and, as a fallback, on a timer.
	pub(crate) fn process(&self) {
		self.process_for(None);
	}

	/// Whether anything is still held for this customer.
	pub(crate) fn has_held(&self, peer: &PublicKey) -> bool {
		self.held.lock().unwrap().iter().any(|h| &h.customer == peer)
	}

	/// The same for one customer: called the moment their channel reads usable or they reconnect, so
	/// a held payment goes out then rather than up to a sweep later (Blocknil patch). Anything
	/// that still can't go stays held, and the timer picks it up.
	pub(crate) fn release_for(&self, peer: PublicKey) {
		self.process_for(Some(peer));
	}

	fn process_for(&self, only: Option<PublicKey>) {
		self.process_onions();
		let now = Instant::now();
		let mut announce = Vec::new();
		let mut short_of_room = Vec::new();
		{
			let mut held = self.held.lock().unwrap();
			let mut keep = Vec::with_capacity(held.len());
			for mut h in held.drain(..) {
				// Only this customer's payments, when one was named.
				if only.is_some_and(|peer| h.customer != peer) {
					keep.push(h);
					continue;
				}
				// What goes to the customer: all of it, or all but the fee for room spliced in for it.
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
							if h.announced || h.fee_msat > 0 {
								self.record(&h, true);
							}
							continue;
						},
						Err(e) => {
							log_debug!(self.logger, "Couldn't forward to {} yet: {:?}", h.customer, e);
						},
					}
				}
				if now >= h.deadline {
					if let Err(e) = self.channel_manager.fail_intercepted_htlc(h.intercept_id) {
						log_error!(self.logger, "Failed to fail back a held payment: {:?}", e);
					}
					log_info!(
						self.logger,
						"Gave up on a held payment of {} msat for customer {}: not back in time",
						h.amount_msat,
						h.customer
					);
					self.record(&h, false);
					continue;
				}
				// Online, with a usable channel that is too small: the provider decides about room,
				// once per payment. An offline customer is woken first, as before.
				let room_msat = channels
					.iter()
					.filter(|c| c.is_usable)
					.map(|c| c.next_outbound_htlc_limit_msat)
					.max();
				let deciding = self.on_short_of_room.read().unwrap().is_some();
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
							customer: h.customer,
							amount_msat: h.amount_msat,
							room_msat,
						});
					}
				} else if !h.announced {
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
		// Outside the lock: the provider's answer comes back through `set_fee` or `refuse`.
		if !short_of_room.is_empty() {
			if let Some(on_short_of_room) = self.on_short_of_room.read().unwrap().clone() {
				for short in short_of_room {
					on_short_of_room(short);
				}
			}
		}
		// Outside the lock: waking the phone may reach out to the network.
		if !announce.is_empty() {
			if let Some(on_held) = self.on_held.read().unwrap().clone() {
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
	fn hold_scids_survive_encoding() {
		let customer: PublicKey =
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		let mut scids = HashMap::new();
		scids.insert(0x0123_4567_89ab_cdef_u64, customer);
		scids.insert(42, customer);
		assert_eq!(decode(&encode(&scids)), scids);
		assert!(decode(b"garbage\n").is_empty());
	}
}
