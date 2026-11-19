// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.

//! Blocknil spike: held payments and splice on arrival on rust-lightning 0.3's
//! `htlc_interception_flags`, without hold SCIDs.
//!
//! With `ToOnlinePrivateChannels | ToOfflinePrivateChannels` set, every HTLC an LSP forwards to a
//! client's private channel is surfaced as `Event::HTLCIntercepted`, whatever the payment type
//! (BOLT11 route hint, BOLT12 blinded path, keysend, an async payment released by the client).
//! The channel is identified by the SCID the payer used, so no per-client intercept SCID has to
//! be handed out or put into invoices. Each intercepted HTLC:
//! - goes out at once when the client's channel is usable and can take it;
//! - is held while the client is offline (the `on_held` callback wakes them) and goes out when
//!   they are back;
//! - is reported once through `on_short_of_room` when the client is online but their channel is
//!   too small; the LSP answers with `set_fee` (after splicing room in) or `refuse`;
//! - is failed back after `hold_for`.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::InterceptId;
use lightning::types::payment::PaymentHash;

use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::ChannelManager;

/// How long a payment is held before it is failed back.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(90);

/// Called with the client whose payment is being held because they are offline.
pub type OnHeld = Arc<dyn Fn(PublicKey) + Send + Sync>;

/// A payment whose client is online, with a usable channel too small for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortOfRoom {
	/// Names the HTLC in the answer.
	pub intercept_id: InterceptId,
	/// The payment the HTLC belongs to.
	pub payment_hash: PaymentHash,
	/// The client the payment is for.
	pub customer: PublicKey,
	/// What the HTLC carries for the client.
	pub amount_msat: u64,
	/// The most the client's channel can take right now.
	pub room_msat: u64,
}

/// Called once per held HTLC that is short of room. Must not block.
pub type OnShortOfRoom = Arc<dyn Fn(ShortOfRoom) + Send + Sync>;

struct Held {
	intercept_id: InterceptId,
	payment_hash: PaymentHash,
	customer: PublicKey,
	amount_msat: u64,
	deadline: Instant,
	announced: bool,
	room_asked: bool,
	fee_msat: u64,
}

pub(crate) struct HeldPayments {
	held: Mutex<Vec<Held>>,
	hold_for: RwLock<Duration>,
	on_held: RwLock<Option<OnHeld>>,
	on_short_of_room: RwLock<Option<OnShortOfRoom>>,
	channel_manager: Arc<ChannelManager>,
	logger: Arc<Logger>,
}

impl HeldPayments {
	pub(crate) fn new(channel_manager: Arc<ChannelManager>, logger: Arc<Logger>) -> Self {
		Self {
			held: Mutex::new(Vec::new()),
			hold_for: RwLock::new(DEFAULT_HOLD),
			on_held: RwLock::new(None),
			on_short_of_room: RwLock::new(None),
			channel_manager,
			logger,
		}
	}

	/// The client whose channel the payer asked for, when it is one of our channels. An
	/// intercept SCID (an LSPS2 just-in-time channel) is not one.
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
		*self.hold_for.write().unwrap() = hold_for;
	}

	pub(crate) fn set_on_held(&self, on_held: OnHeld) {
		*self.on_held.write().unwrap() = Some(on_held);
	}

	pub(crate) fn set_on_short_of_room(&self, on_short_of_room: OnShortOfRoom) {
		*self.on_short_of_room.write().unwrap() = Some(on_short_of_room);
	}

	pub(crate) fn intercepted(
		&self, intercept_id: InterceptId, payment_hash: PaymentHash, customer: PublicKey,
		amount_msat: u64,
	) {
		let deadline = Instant::now() + *self.hold_for.read().unwrap();
		self.held.lock().unwrap().push(Held {
			intercept_id,
			payment_hash,
			customer,
			amount_msat,
			deadline,
			announced: false,
			room_asked: false,
			fee_msat: 0,
		});
		self.process();
	}

	/// Forward this HTLC less `fee_msat` as soon as it fits.
	pub(crate) fn set_fee(&self, intercept_id: InterceptId, fee_msat: u64) -> bool {
		let found = {
			let mut held = self.held.lock().unwrap();
			match held.iter_mut().find(|h| h.intercept_id == intercept_id) {
				Some(h) => {
					h.fee_msat = fee_msat.min(h.amount_msat);
					true
				},
				None => false,
			}
		};
		if found {
			self.process();
		}
		found
	}

	/// Fail this HTLC back now.
	pub(crate) fn refuse(&self, intercept_id: InterceptId) -> bool {
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
		true
	}

	/// Payments held right now: `(customer, payment_hash, amount_msat)`.
	pub(crate) fn held(&self) -> Vec<(PublicKey, PaymentHash, u64)> {
		self.held
			.lock()
			.unwrap()
			.iter()
			.map(|h| (h.customer, h.payment_hash, h.amount_msat))
			.collect()
	}

	/// Forwards what can go now, fails back what waited too long, and reports newly held
	/// payments. Runs on every interception and on a timer.
	pub(crate) fn process(&self) {
		let now = Instant::now();
		let mut announce = Vec::new();
		let mut short_of_room = Vec::new();
		{
			let mut held = self.held.lock().unwrap();
			let mut keep = Vec::with_capacity(held.len());
			for mut h in held.drain(..) {
				let forward_msat = h.amount_msat - h.fee_msat;
				let channels: Vec<_> = self
					.channel_manager
					.list_channels_with_counterparty(&h.customer)
					.into_iter()
					.filter(|c| c.is_usable)
					.collect();
				let fits = channels
					.iter()
					.filter(|c| c.next_outbound_htlc_limit_msat >= forward_msat)
					.max_by_key(|c| c.next_outbound_htlc_limit_msat);
				if let Some(channel) = fits {
					match self.channel_manager.forward_intercepted_htlc(
						h.intercept_id,
						&channel.channel_id,
						h.customer,
						forward_msat,
					) {
						Ok(()) => {
							log_info!(
								self.logger,
								"Forwarded {} msat to {} (fee kept {} msat)",
								forward_msat,
								h.customer,
								h.fee_msat
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
					let _ = self.channel_manager.fail_intercepted_htlc(h.intercept_id);
					log_info!(self.logger, "Gave up on a held payment for {}", h.customer);
					continue;
				}
				let room_msat = channels.iter().map(|c| c.next_outbound_htlc_limit_msat).max();
				let deciding = self.on_short_of_room.read().unwrap().is_some();
				match (room_msat, deciding) {
					(Some(room_msat), true) if h.fee_msat == 0 => {
						if !h.room_asked {
							h.room_asked = true;
							short_of_room.push(ShortOfRoom {
								intercept_id: h.intercept_id,
								payment_hash: h.payment_hash,
								customer: h.customer,
								amount_msat: h.amount_msat,
								room_msat,
							});
						}
					},
					(None, _) if !h.announced => {
						h.announced = true;
						log_info!(
							self.logger,
							"Holding a payment for {} until they're back",
							h.customer
						);
						announce.push(h.customer);
					},
					_ => {},
				}
				keep.push(h);
			}
			*held = keep;
		}
		if let Some(f) = self.on_short_of_room.read().unwrap().clone() {
			for s in short_of_room {
				f(s);
			}
		}
		if let Some(f) = self.on_held.read().unwrap().clone() {
			for c in announce {
				f(c);
			}
		}
	}
}
