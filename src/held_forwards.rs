// Blocknil patch: hold a payment for a customer whose phone is offline, instead of failing it.
//
// A payment to a channel whose peer is disconnected fails at once (`ChannelDisabled`), and a
// phone is disconnected whenever its app isn't on screen. LDK can only hold a payment that
// arrives on an intercept SCID, so each customer gets one (`scid_for`, kept in the store so
// invoices stay valid across restarts) and puts it in its invoices' route hints. A payment on it
// is forwarded at once when the customer's channel is usable; otherwise it is held, the
// `on_held` callback is told (to wake the phone, docs/push-wake-plan.md), and it goes through as
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
}

struct Held {
	intercept_id: InterceptId,
	customer: PublicKey,
	amount_msat: u64,
	since: Instant,
	deadline: Instant,
	announced: bool,
}

pub(crate) struct HeldForwards {
	scids: RwLock<HashMap<u64, PublicKey>>,
	held: Mutex<Vec<Held>>,
	recent: Mutex<VecDeque<HoldRecord>>,
	onions: Mutex<Vec<(PublicKey, Vec<OnionMessage>, Instant)>>,
	hold_for: RwLock<Duration>,
	on_held: RwLock<Option<OnHeld>>,
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
		let ended_at =
			SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default();
		let mut recent = self.recent.lock().unwrap();
		recent.push_front(HoldRecord {
			customer: h.customer,
			amount_msat: h.amount_msat,
			held_secs: h.since.elapsed().as_secs(),
			ended_at,
			forwarded,
		});
		recent.truncate(RECENT);
	}

	/// Whether the peer is ready to answer an onion message: it has a usable channel with us, or
	/// none that could become usable (no channel at all, or only ones still opening).
	fn ready_for_onions(&self, peer: &PublicKey) -> bool {
		let channels = self.channel_manager.list_channels_with_counterparty(peer);
		channels.iter().any(|c| c.is_usable) || !channels.iter().any(|c| c.is_channel_ready)
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
		});
		self.process();
	}

	/// Forwards what can go now, fails back what has waited too long, and announces newly held
	/// payments. Runs on every interception and on a short timer.
	pub(crate) fn process(&self) {
		self.process_onions();
		let now = Instant::now();
		let mut announce = Vec::new();
		{
			let mut held = self.held.lock().unwrap();
			let mut keep = Vec::with_capacity(held.len());
			for mut h in held.drain(..) {
				let channel = self
					.channel_manager
					.list_channels_with_counterparty(&h.customer)
					.into_iter()
					.filter(|c| c.is_usable && c.next_outbound_htlc_limit_msat >= h.amount_msat)
					.max_by_key(|c| c.next_outbound_htlc_limit_msat);
				if let Some(channel) = channel {
					match self.channel_manager.forward_intercepted_htlc(
						h.intercept_id,
						&channel.channel_id,
						h.customer,
						h.amount_msat,
					) {
						Ok(()) => {
							log_info!(
								self.logger,
								"Forwarded a payment of {} msat to customer {}{}",
								h.amount_msat,
								h.customer,
								if h.announced { " after holding it" } else { "" }
							);
							if h.announced {
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
				if !h.announced {
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
			"03daed051c95d71b621a5b392791024cd9cd2487b24d3d6f31c49910e3d7116436".parse().unwrap();
		let mut scids = HashMap::new();
		scids.insert(0x0123_4567_89ab_cdef_u64, customer);
		scids.insert(42, customer);
		assert_eq!(decode(&encode(&scids)), scids);
		assert!(decode(b"garbage\n").is_empty());
	}
}
