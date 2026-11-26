// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::ops::Deref;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use bitcoin::{FeeRate, Transaction};
use chrono::Utc;
use lightning::events::HTLCHandlingFailureType;
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::types::ChannelId;
use lightning::sign::EntropySource;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig as LdkLSPS2ServiceConfig;
use lightning_types::payment::PaymentHash;

use super::jit_wait::JitWaits;
use crate::fee_estimator::{ConfirmationTarget, FeeEstimator, OnchainFeeEstimator};
use crate::logger::{log_error, log_info, log_trace, log_warn, LdkLogger};
use crate::types::{ChannelManager, KeysManager, LiquidityManager, PeerManager, Wallet};
use crate::{total_anchor_channels_reserve_sats, Config};

const LSPS2_CHANNEL_CLTV_EXPIRY_DELTA: u32 = 72;

/// Blocknil patch: the smallest just-in-time channel we open, whatever the payment. Sized to the
/// payment alone, a first payment of a few hundred sats makes a channel under the client's
/// 1,000 sat reserve floor, which the client refuses, and a few thousand sats makes one too small
/// to receive anything after it. Every small first payment ties up this much of our liquidity.
const MIN_JIT_CHANNEL_SATS: u64 = 25_000;

pub(crate) struct LSPS2Service {
	pub(crate) service_config: LSPS2ServiceConfig,
	pub(crate) ldk_service_config: LdkLSPS2ServiceConfig,
}

pub(crate) struct LSPS2ServiceLiquiditySource<L: Deref>
where
	L::Target: LdkLogger,
{
	pub(crate) lsps2_service: Option<LSPS2Service>,
	pub(crate) wallet: Arc<Wallet>,
	pub(crate) fee_estimator: Arc<OnchainFeeEstimator>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) peer_manager: RwLock<Option<Weak<PeerManager>>>,
	pub(crate) keys_manager: Arc<KeysManager>,
	pub(crate) liquidity_manager: Arc<LiquidityManager>,
	pub(crate) config: Arc<Config>,
	pub(crate) logger: L,
	/// First payments waiting for their offline client. Blocknil patch: see `jit_wait`.
	pub(crate) jit_waits: JitWaits,
	/// How many HTLCs the sweep at the first start failed back; `None` before it ran. Blocknil
	/// patch.
	pub(crate) stuck_channel_opens_failed: std::sync::Mutex<Option<usize>>,
}

/// Represents the configuration of the LSPS2 service.
///
/// See [bLIP-52 / LSPS2] for more information.
///
/// [bLIP-52 / LSPS2]: https://github.com/lightning/blips/blob/master/blip-0052.md
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LSPS2ServiceConfig {
	/// A token we may require to be sent by the clients.
	///
	/// If set, only requests matching this token will be accepted.
	pub require_token: Option<String>,
	/// Indicates whether the LSPS service will be announced via the gossip network.
	pub advertise_service: bool,
	/// The fee we withhold for the channel open from the initial payment.
	///
	/// This fee is proportional to the client-requested amount, in parts-per-million.
	pub channel_opening_fee_ppm: u32,
	/// The proportional overprovisioning for the channel.
	///
	/// This determines, in parts-per-million, how much value we'll provision on top of the amount
	/// we need to forward the payment to the client.
	///
	/// For example, setting this to `100_000` will result in a channel being opened that is 10%
	/// larger than then the to-be-forwarded amount (i.e., client-requested amount minus the
	/// channel opening fee fee).
	pub channel_over_provisioning_ppm: u32,
	/// The minimum fee required for opening a channel.
	pub min_channel_opening_fee_msat: u64,
	/// The minimum number of blocks after confirmation we promise to keep the channel open.
	pub min_channel_lifetime: u32,
	/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
	pub max_client_to_self_delay: u32,
	/// The minimum payment size that we will accept when opening a channel.
	pub min_payment_size_msat: u64,
	/// The maximum payment size that we will accept when opening a channel.
	pub max_payment_size_msat: u64,
	/// Use the 'client-trusts-LSP' trust model.
	///
	/// When set, the service will delay *broadcasting* the JIT channel's funding transaction until
	/// the client claimed sufficient HTLC parts to pay for the channel open.
	///
	/// Note this will render the flow incompatible with clients utilizing the 'LSP-trust-client'
	/// trust model, i.e., in turn delay *claiming* any HTLCs until they see the funding
	/// transaction in the mempool.
	///
	/// Please refer to [`bLIP-52`] for more information.
	///
	/// [`bLIP-52`]: https://github.com/lightning/blips/blob/master/blip-0052.md#trust-models
	pub client_trusts_lsp: bool,
	/// When set, we will allow clients to spend their entire channel balance in the channels
	/// we open to them. This allows clients to try to steal your channel balance with
	/// no financial penalty, so this should only be set if you trust your clients.
	///
	/// See [`Node::open_0reserve_channel`] to manually open these channels.
	///
	/// [`Node::open_0reserve_channel`]: crate::Node::open_0reserve_channel
	pub disable_client_reserve: bool,
	/// How long the opening fee parameters we offer stay valid, in seconds.
	///
	/// Blocknil patch: upstream fixes this at 48 hours. Until it lapses, an offer a client bought
	/// an intercept SCID with holds one of the ten LSPS2 slots each client gets, even if nobody
	/// pays the invoice built on it, so a long lifetime lets a client run out of slots.
	///
	/// It can't be short either: an LDK Node client only takes parameters that outlive the invoice
	/// it builds on them by 10 minutes plus its 5 second request timeout. That is 1 h 10 min 5 s
	/// for a one-hour BOLT11 invoice and 2 h 10 min 5 s for a BOLT12 one (it uses two-hour
	/// invoices). Its lease cache, which keeps a bought lease ready per BOLT12 offer amount, only
	/// takes parameters valid for at least 24 hours more; below that it buys a lease only when an
	/// invoice is asked for. Upstream's value is [`DEFAULT_OPENING_FEE_PARAMS_LIFETIME_SECS`]; see
	/// [`SHORT_OPENING_FEE_PARAMS_LIFETIME_SECS`] for the shortest that serves both invoice kinds.
	pub opening_fee_params_lifetime_secs: u64,
	/// What opening a channel costs us on chain, to set the offer's minimum fee and minimum
	/// payment from the fee rate when the offer is made.
	///
	/// Blocknil patch: when set, [`Self::min_channel_opening_fee_msat`] and
	/// [`Self::min_payment_size_msat`] are not used. A fixed minimum fee is either too low when
	/// fees rise (a small first payment then costs us more in mining fees than it pays) or too
	/// high when they fall. Upstream has no such option.
	pub opening_cost: Option<JitOpeningCost>,
}

/// What a just-in-time channel costs its LSP on chain, from which its minimum opening fee and
/// minimum payment follow the fee rate. Blocknil patch: see [`LSPS2ServiceConfig::opening_cost`].
///
/// At `ChannelFunding`'s fee rate `r` when an offer is made:
/// `min fee = max(floor, ⌈(open + close vbytes) × r × headroom⌉ + close margin)`, and
/// `min payment = min fee + min_payment_over_fee_sats`. The opening fee itself stays bLIP-52's:
/// the larger of the minimum fee and the proportional share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct JitOpeningCost {
	/// The funding transaction's size, in vbytes.
	pub open_vbytes: u64,
	/// The closing transaction's size, in vbytes: paid later, by us as the channel's funder.
	pub close_vbytes: u64,
	/// How much the fee rate is raised for this, in parts per million (1,000,000 is 1×): the rate
	/// can rise while an offer is valid, and the close comes later at an unknown one.
	pub feerate_headroom_ppm: u32,
	/// What the close may cost over its size at the fee rate, as LDK's
	/// `force_close_avoidance_max_fee_satoshis` lets it.
	pub close_fee_margin_sats: u64,
	/// The smallest minimum fee, whatever the fee rate.
	pub min_fee_floor_sats: u64,
	/// What the smallest first payment leaves the client after the minimum fee.
	pub min_payment_over_fee_sats: u64,
}

impl JitOpeningCost {
	/// The minimum opening fee at `fee_rate`, in msat, rounded up to the sat. Saturates at
	/// `u64::MAX` rather than overflowing.
	pub fn min_fee_msat(&self, fee_rate: FeeRate) -> u64 {
		let weight = (self.open_vbytes as u128).saturating_add(self.close_vbytes as u128) * 4;
		// sat/kWU × WU / 1,000 = sats, and the headroom is in ppm.
		let onchain_sats = weight
			.saturating_mul(fee_rate.to_sat_per_kwu() as u128)
			.saturating_mul(self.feerate_headroom_ppm as u128)
			.div_ceil(1_000 * 1_000_000);
		let fee_sats = onchain_sats
			.saturating_add(self.close_fee_margin_sats as u128)
			.max(self.min_fee_floor_sats as u128);
		u64::try_from(fee_sats.saturating_mul(1_000)).unwrap_or(u64::MAX)
	}

	/// The minimum payment at `fee_rate`, in msat: the minimum fee plus what it leaves the client.
	pub fn min_payment_size_msat(&self, fee_rate: FeeRate) -> u64 {
		self.min_fee_msat(fee_rate)
			.saturating_add(self.min_payment_over_fee_sats.saturating_mul(1_000))
	}
}

/// The minimum opening fee and minimum payment of the offer we make, in msat: from
/// `opening_cost` at `fee_rate` when it is set, the static ones otherwise. Blocknil patch.
///
/// `None`, no offer, when the minimum payment is over `max_payment_msat`: bLIP-52 wants the
/// minimum at or under the maximum, and no payment the offer allows would pay for the open (with
/// `opening_cost`, at high fee rates). Lowering the minimum to the maximum instead would open
/// channels for less than they cost on chain.
fn offered_minimums(
	opening_cost: Option<JitOpeningCost>, static_min_fee_msat: u64, static_min_payment_msat: u64,
	max_payment_msat: u64, fee_rate: FeeRate,
) -> Option<(u64, u64)> {
	let (min_fee_msat, min_payment_msat) = match opening_cost {
		Some(cost) => (cost.min_fee_msat(fee_rate), cost.min_payment_size_msat(fee_rate)),
		None => (static_min_fee_msat, static_min_payment_msat),
	};
	(min_payment_msat <= max_payment_msat).then_some((min_fee_msat, min_payment_msat))
}

/// Upstream's lifetime of the opening fee parameters we offer: 48 hours. Long enough for an LDK
/// Node client to cache leases. Blocknil patch: see
/// [`LSPS2ServiceConfig::opening_fee_params_lifetime_secs`].
pub const DEFAULT_OPENING_FEE_PARAMS_LIFETIME_SECS: u64 = 48 * 60 * 60;

/// The shortest lifetime of our opening fee parameters an LDK Node client accepts for both BOLT11
/// invoices of up to one hour and BOLT12 invoices (two hours): 2 h 15 min, which leaves 4 min 55 s
/// over the 2 h 10 min 5 s the BOLT12 path needs for the request round trip and the clocks of the
/// two nodes disagreeing. Clients can't cache leases on it, so a lease, and the slot it holds,
/// exists only for an invoice actually asked for, and lapses 2 h 15 min later if it isn't paid.
/// Blocknil patch.
pub const SHORT_OPENING_FEE_PARAMS_LIFETIME_SECS: u64 = 2 * 60 * 60 + 15 * 60;

impl<L: Deref> LSPS2ServiceLiquiditySource<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn set_peer_manager(&self, peer_manager: Weak<PeerManager>) {
		*self.peer_manager.write().expect("lock") = Some(peer_manager);
	}

	pub(crate) fn liquidity_manager(&self) -> Arc<LiquidityManager> {
		Arc::clone(&self.liquidity_manager)
	}

	pub(crate) fn lsps2_channel_needs_manual_broadcast(
		&self, counterparty_node_id: PublicKey, user_channel_id: u128,
	) -> bool {
		self.lsps2_service.as_ref().map_or(false, |lsps2_service| {
			lsps2_service.service_config.client_trusts_lsp
				&& self
					.liquidity_manager()
					.lsps2_service_handler()
					.and_then(|handler| {
						handler
							.channel_needs_manual_broadcast(user_channel_id, &counterparty_node_id)
							.ok()
					})
					.unwrap_or(false)
		})
	}

	/// Blocknil patch: whether we, as an LSPS2 service, keep no reserve on our clients' side: for
	/// channels we open to them, and (in the `OpenChannelRequest` handler) channels they open to us.
	pub(crate) fn disables_client_reserve(&self) -> bool {
		self.lsps2_service.as_ref().is_some_and(|s| s.service_config.disable_client_reserve)
	}

	pub(crate) fn lsps2_store_funding_transaction(
		&self, user_channel_id: u128, counterparty_node_id: PublicKey, funding_tx: Transaction,
	) {
		let Some(lsps2_service) = self.lsps2_service.as_ref() else { return };
		if !lsps2_service.service_config.client_trusts_lsp {
			// Only necessary for client-trusts-LSP flow
			return;
		}

		let lsps2_service_handler = self.liquidity_manager.lsps2_service_handler();
		if let Some(handler) = lsps2_service_handler {
			handler
				.store_funding_transaction(user_channel_id, &counterparty_node_id, funding_tx)
				.unwrap_or_else(|e| {
					debug_assert!(false, "Failed to store funding transaction: {:?}", e);
					log_error!(self.logger, "Failed to store funding transaction: {:?}", e);
				});
		} else {
			log_error!(self.logger, "LSPS2 service handler is not available.");
		}
	}

	pub(crate) fn lsps2_funding_tx_broadcast_safe(
		&self, user_channel_id: u128, counterparty_node_id: PublicKey,
	) {
		let Some(lsps2_service) = self.lsps2_service.as_ref() else { return };
		if !lsps2_service.service_config.client_trusts_lsp {
			// Only necessary for client-trusts-LSP flow
			return;
		}

		let lsps2_service_handler = self.liquidity_manager.lsps2_service_handler();
		if let Some(handler) = lsps2_service_handler {
			handler
				.set_funding_tx_broadcast_safe(user_channel_id, &counterparty_node_id)
				.unwrap_or_else(|e| {
					debug_assert!(
						false,
						"Failed to mark funding transaction safe to broadcast: {:?}",
						e
					);
					log_error!(
						self.logger,
						"Failed to mark funding transaction safe to broadcast: {:?}",
						e
					);
				});
		} else {
			log_error!(self.logger, "LSPS2 service handler is not available.");
		}
	}

	pub(crate) async fn handle_channel_ready(
		&self, user_channel_id: u128, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) {
		// Blocknil patch: the open is done; a later close is an ordinary one.
		self.jit_waits.remove(user_channel_id);
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.channel_ready(user_channel_id, channel_id, counterparty_node_id)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle ChannelReady event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_htlc_intercepted(
		&self, intercept_scid: u64, intercept_id: InterceptId, expected_outbound_amount_msat: u64,
		payment_hash: PaymentHash, inbound_amount_msat: u64,
	) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.htlc_intercepted(
					intercept_scid,
					intercept_id,
					expected_outbound_amount_msat,
					payment_hash,
					inbound_amount_msat,
				)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle HTLCIntercepted event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_htlc_handling_failed(&self, failure_type: HTLCHandlingFailureType) {
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler.htlc_handling_failed(failure_type).await {
				log_error!(
					self.logger,
					"LSPS2 service failed to handle HTLCHandlingFailed event: {:?}",
					e
				);
			}
		}
	}

	pub(crate) async fn handle_payment_forwarded(
		&self, next_channel_id: Option<ChannelId>, skimmed_fee_msat: u64,
	) {
		if let Some(next_channel_id) = next_channel_id {
			if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
				if let Err(e) =
					lsps2_service_handler.payment_forwarded(next_channel_id, skimmed_fee_msat).await
				{
					log_error!(
						self.logger,
						"LSPS2 service failed to handle PaymentForwarded: {:?}",
						e
					);
				}
			}
		}
	}

	pub(crate) async fn handle_channel_closed(
		&self, user_channel_id: u128, channel_id: ChannelId, counterparty_node_id: &PublicKey,
		disconnected: bool, funding_generated: bool,
	) {
		// Blocknil patch: a client that dropped mid-open (a phone whose app went to the
		// background) is waited for again rather than its payment failed back; see `jit_wait`.
		let rewait = self.jit_waits.channel_closed(
			user_channel_id,
			channel_id,
			disconnected,
			funding_generated,
			Instant::now(),
		);
		if rewait {
			log_info!(
				self.logger,
				"LSPS2 channel to {} closed mid-open as the client disconnected; its first payment waits for the client again.",
				counterparty_node_id,
			);
		}
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			// A JIT channel closing before it became ready is a failed channel open. This errors
			// for any channel that isn't such a JIT channel, which is the common case.
			// Blocknil patch: unless its payment waits for the client again.
			let failed = if rewait {
				Ok(())
			} else {
				lsps2_service_handler
					.channel_open_failed(counterparty_node_id, user_channel_id)
					.await
			};
			if let Err(e) = failed {
				log_trace!(
					self.logger,
					"LSPS2 service did not treat the closure of channel {} as a failed channel open: {:?}",
					channel_id,
					e
				);
			}

			if let Err(e) = lsps2_service_handler.channel_closed(channel_id).await {
				log_error!(
					self.logger,
					"LSPS2 service failed to handle ChannelClosed event: {:?}",
					e
				);
			}
		}
	}

	/// Fails the HTLCs held for the given JIT channel back, allowing the payer to retry.
	async fn fail_channel_open(&self, counterparty_node_id: &PublicKey, user_channel_id: u128) {
		// Blocknil patch: the payment no longer waits.
		self.jit_waits.remove(user_channel_id);
		if let Some(lsps2_service_handler) = self.liquidity_manager.lsps2_service_handler() {
			if let Err(e) = lsps2_service_handler
				.channel_open_failed(counterparty_node_id, user_channel_id)
				.await
			{
				log_error!(
					self.logger,
					"LSPS2 service failed to handle failed channel open: {:?}",
					e
				);
			}
		}
	}

	/// Blocknil patch: retries the opens whose client is now connected and fails back the first
	/// payments whose client didn't come in time. Called every second while the node runs.
	pub(crate) async fn process_jit_waits(&self) {
		let peer_manager =
			self.peer_manager.read().expect("lock").as_ref().and_then(|weak| weak.upgrade());
		let Some(peer_manager) = peer_manager else { return };
		let (retry, expired) = self
			.jit_waits
			.take_due(Instant::now(), |client| peer_manager.peer_by_node_id(client).is_some());
		for (client, user_channel_id) in expired {
			log_info!(
				self.logger,
				"Gave up on the first payment for {}: the client didn't connect in time.",
				client,
			);
			self.fail_channel_open(&client, user_channel_id).await;
		}
		for open_channel in retry {
			self.handle_event(open_channel).await;
		}
	}

	/// Blocknil patch: once per node, at its first start: fails back the payments of JIT flows
	/// waiting on a channel open whose channel doesn't exist, which at startup means the open was
	/// lost with the restart. See `LSPS2ServiceHandler::fail_stuck_channel_opens` (our
	/// rust-lightning patch rl-01). Later starts of the same node keep their opens in memory, so
	/// they don't sweep: a first payment waiting for its client (`jit_wait`) has no channel either.
	///
	/// Returns whether it ran (the first start).
	pub(crate) async fn fail_stuck_channel_opens_at_first_start(&self) -> bool {
		if self.stuck_channel_opens_failed.lock().expect("lock").is_some() {
			return false;
		}
		let failed = match self.liquidity_manager.lsps2_service_handler() {
			Some(handler) => handler.fail_stuck_channel_opens().await,
			None => 0,
		};
		if failed > 0 {
			log_info!(
				self.logger,
				"Failed back {} HTLC(s) held for JIT channel opens lost with the restart.",
				failed
			);
		}
		*self.stuck_channel_opens_failed.lock().expect("lock") = Some(failed);
		true
	}

	/// Blocknil patch: how many HTLCs `fail_stuck_channel_opens_at_first_start` failed back.
	pub(crate) fn stuck_channel_opens_failed(&self) -> usize {
		self.stuck_channel_opens_failed.lock().expect("lock").unwrap_or(0)
	}

	/// Blocknil patch: LDK released the coins of a discarded channel funding; an open that waited
	/// on it may restart.
	pub(crate) fn handle_funding_discarded(&self, channel_id: ChannelId) {
		self.jit_waits.funding_discarded(channel_id);
	}

	pub(crate) async fn handle_event(&self, event: LSPS2ServiceEvent) {
		match event {
			LSPS2ServiceEvent::GetInfo { request_id, counterparty_node_id, token } => {
				if let Some(lsps2_service_handler) =
					self.liquidity_manager.lsps2_service_handler().as_ref()
				{
					let service_config = if let Some(service_config) =
						self.lsps2_service.as_ref().map(|s| s.service_config.clone())
					{
						service_config
					} else {
						log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
						return;
					};

					if let Some(required) = service_config.require_token {
						if token != Some(required) {
							log_error!(
								self.logger,
								"Rejecting LSPS2 request {:?} from counterparty {} as the client provided an invalid token.",
								request_id,
								counterparty_node_id
							);
							lsps2_service_handler.invalid_token_provided(&counterparty_node_id, request_id.clone()).unwrap_or_else(|e| {
								debug_assert!(false, "Failed to reject LSPS2 request. This should never happen.");
								log_error!(
									self.logger,
									"Failed to reject LSPS2 request {:?} from counterparty {} due to: {:?}. This should never happen.",
									request_id,
									counterparty_node_id,
									e
								);
							});
							return;
						}
					}

					// Blocknil patch: the lifetime is configured (upstream: 48 hours).
					let lifetime =
						Duration::from_secs(service_config.opening_fee_params_lifetime_secs);
					let valid_until = LSPSDateTime(Utc::now() + lifetime);
					// Blocknil patch: with an opening cost, the minimums follow today's fee rate.
					let fee_rate = service_config.opening_cost.map(|_| {
						self.fee_estimator.estimate_fee_rate(ConfirmationTarget::ChannelFunding)
					});
					// An empty menu when no payment could pay for the open (see `offered_minimums`).
					let opening_fee_params_menu = match offered_minimums(
						service_config.opening_cost,
						service_config.min_channel_opening_fee_msat,
						service_config.min_payment_size_msat,
						service_config.max_payment_size_msat,
						fee_rate.unwrap_or(FeeRate::ZERO),
					) {
						Some((min_fee_msat, min_payment_size_msat)) => {
							vec![LSPS2RawOpeningFeeParams {
								min_fee_msat,
								proportional: service_config.channel_opening_fee_ppm,
								valid_until,
								min_lifetime: service_config.min_channel_lifetime,
								max_client_to_self_delay: service_config.max_client_to_self_delay,
								min_payment_size_msat,
								max_payment_size_msat: service_config.max_payment_size_msat,
							}]
						},
						None => {
							log_warn!(
								self.logger,
								"Offering no JIT channel to {}: at {} sat/kWU the minimum payment would be over the maximum of {} msat",
								counterparty_node_id,
								fee_rate.map_or(0, |rate| rate.to_sat_per_kwu()),
								service_config.max_payment_size_msat,
							);
							Vec::new()
						},
					};

					if let Err(e) = lsps2_service_handler.opening_fee_params_generated(
						&counterparty_node_id,
						request_id,
						opening_fee_params_menu,
					) {
						log_error!(
							self.logger,
							"Failed to handle generated opening fee params: {:?}",
							e
						);
					}
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				}
			},
			LSPS2ServiceEvent::BuyRequest {
				request_id,
				counterparty_node_id,
				opening_fee_params,
				payment_size_msat,
			} => {
				if let Some(lsps2_service_handler) =
					self.liquidity_manager.lsps2_service_handler().as_ref()
				{
					let service_config = if let Some(service_config) =
						self.lsps2_service.as_ref().map(|s| s.service_config.clone())
					{
						service_config
					} else {
						log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
						return;
					};

					let user_channel_id: u128 = u128::from_ne_bytes(
						self.keys_manager.get_secure_random_bytes()[..16]
							.try_into()
							.expect("a 16-byte slice should convert into a [u8; 16]"),
					);
					let intercept_scid = self.channel_manager.get_intercept_scid();

					if let Some(payment_size_msat) = payment_size_msat {
						// We already check this in `lightning-liquidity`, but better safe than
						// sorry.
						//
						// TODO: We might want to eventually send back an error here, but we
						// currently can't and have to trust `lightning-liquidity` is doing the
						// right thing.
						//
						// TODO: Eventually we also might want to make sure that we have sufficient
						// liquidity for the channel opening here.
						//
						// Blocknil patch: against the parameters the client bought, which with an
						// `opening_cost` aren't the static ones.
						if payment_size_msat > opening_fee_params.max_payment_size_msat
							|| payment_size_msat < opening_fee_params.min_payment_size_msat
						{
							log_error!(
								self.logger,
								"Rejecting to handle LSPS2 buy request {:?} from counterparty {} as the client requested an invalid payment size.",
								request_id,
								counterparty_node_id
							);
							return;
						}
					}

					match lsps2_service_handler
						.invoice_parameters_generated(
							&counterparty_node_id,
							request_id,
							intercept_scid,
							LSPS2_CHANNEL_CLTV_EXPIRY_DELTA,
							service_config.client_trusts_lsp,
							user_channel_id,
						)
						.await
					{
						Ok(()) => {},
						Err(e) => {
							log_error!(
								self.logger,
								"Failed to provide invoice parameters: {:?}",
								e
							);
							return;
						},
					}
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				}
			},
			LSPS2ServiceEvent::OpenChannel {
				their_network_key,
				amt_to_forward_msat,
				opening_fee_msat,
				user_channel_id,
				intercept_scid,
				max_client_to_self_delay,
			} => {
				if self.liquidity_manager.lsps2_service_handler().is_none() {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				};

				// Blocknil patch: remember the open, so it can wait for the client and be retried
				// (`process_jit_waits` hands this event back).
				let open_channel = LSPS2ServiceEvent::OpenChannel {
					their_network_key,
					amt_to_forward_msat,
					opening_fee_msat,
					user_channel_id,
					intercept_scid,
					max_client_to_self_delay,
				};
				let first_attempt = self.jit_waits.opening(open_channel, Instant::now());

				let service_config = if let Some(service_config) =
					self.lsps2_service.as_ref().map(|s| s.service_config.clone())
				{
					service_config
				} else {
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as LSPS2 liquidity service was not configured.",);
					return;
				};

				let peer_manager = self
					.peer_manager
					.read()
					.expect("lock")
					.as_ref()
					.and_then(|weak| weak.upgrade());
				let Some(peer_manager) = peer_manager else {
					debug_assert!(false, "Failed to handle LSPS2ServiceEvent as peer manager isn't available. This should never happen.",);
					log_error!(self.logger, "Failed to handle LSPS2ServiceEvent as peer manager isn't available. This should never happen.",);
					return;
				};

				// Fail if we're not connected to the prospective channel partner.
				let Some(peer) = peer_manager.peer_by_node_id(&their_network_key) else {
					// Blocknil patch: wait for the client (and wake it) instead, while the wait
					// lasts; upstream's TODO below.
					if self.jit_waits.wait_for_client(user_channel_id, Instant::now()) {
						log_info!(
							self.logger,
							"LSPS2 channel to {} waits for the client to connect.",
							their_network_key,
						);
						if first_attempt {
							self.jit_waits.wake(their_network_key);
						}
						return;
					}
					log_error!(
						self.logger,
						"Failed to open LSPS2 channel to {} due to peer not being connected.",
						their_network_key,
					);
					// TODO: We fail the payment back here. Eventually we will need to remember
					// the pending requests and regularly retry opening the channel until we
					// succeed.
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				};
				let init_features = peer.init_features;

				// Fail if we have insufficient onchain funds available.
				let over_provisioning_msat = amt_to_forward_msat
					.saturating_mul(service_config.channel_over_provisioning_ppm as u64)
					/ 1_000_000;
				// Blocknil patch: never smaller than `MIN_JIT_CHANNEL_SATS`.
				let channel_amount_sats =
					(amt_to_forward_msat.saturating_add(over_provisioning_msat) / 1000)
						.max(MIN_JIT_CHANNEL_SATS);
				let cur_anchor_reserve_sats =
					total_anchor_channels_reserve_sats(&self.channel_manager, &self.config);
				let spendable_amount_sats =
					self.wallet.get_spendable_amount_sats(cur_anchor_reserve_sats).unwrap_or(0);
				let anchor_channel =
					crate::peer_may_negotiate_anchor_channel_type(&self.config, &init_features);
				let additional_reserve_required = crate::new_channel_anchor_reserve_sats(
					&self.config,
					&their_network_key,
					anchor_channel,
				);
				let required_funds_sats =
					channel_amount_sats.saturating_add(additional_reserve_required);
				if spendable_amount_sats < required_funds_sats {
					log_error!(self.logger,
						"Unable to create channel due to insufficient funds. Available: {}sats, Required: {}sats",
						spendable_amount_sats, required_funds_sats,
					);
					// TODO: We fail the payment back here. Eventually we will need to remember
					// the pending requests and regularly retry opening the channel until we
					// succeed.
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				}

				// The funding transaction's fee is paid from the same on-chain funds, so we can't
				// fund more than we would when opening a channel with all of them.
				let total_anchor_reserve_sats =
					cur_anchor_reserve_sats.saturating_add(additional_reserve_required);
				let funding_fee_rate =
					self.fee_estimator.estimate_fee_rate(ConfirmationTarget::ChannelFunding);
				let max_amount = match self
					.wallet
					.get_max_funding_amount(total_anchor_reserve_sats, funding_fee_rate)
				{
					Ok(max_amount) => max_amount,
					Err(e) => {
						log_error!(
							self.logger,
							"Unable to create channel as the maximum funding amount couldn't be determined: {:?}",
							e,
						);
						self.fail_channel_open(&their_network_key, user_channel_id).await;
						return;
					},
				};
				if channel_amount_sats > max_amount {
					log_error!(self.logger,
						"Unable to create channel due to insufficient funds. Requested: {}sats, Maximum: {}sats (fee rate: {} sat/kw, anchor reserve: {}sats)",
						channel_amount_sats, max_amount, funding_fee_rate.to_sat_per_kwu(), total_anchor_reserve_sats,
					);
					self.fail_channel_open(&their_network_key, user_channel_id).await;
					return;
				}

				let mut config = self.channel_manager.get_current_config().clone();

				// The client's `to_self_delay` must not exceed the maximum promised in the opening fee
				// parameters it selected. Events persisted before rust-lightning 0.3 carry no bound.
				if let Some(max_client_to_self_delay) = max_client_to_self_delay {
					let ours = config.channel_handshake_limits.their_to_self_delay;
					config.channel_handshake_limits.their_to_self_delay =
						u32::from(ours).min(max_client_to_self_delay) as u16;
				}

				// If we act as an LSPS2 service, the HTLC-value-in-flight must be 100% of the
				// channel value to ensure we can forward the initial payment. That cap only
				// applies to unannounced channels, so the channel must also be unannounced.
				debug_assert_eq!(
					config
						.channel_handshake_config
						.unannounced_channel_max_inbound_htlc_value_in_flight_percentage,
					100
				);
				debug_assert!(!config.channel_handshake_config.announce_for_forwarding);
				debug_assert!(config.accept_forwards_to_priv_channels);

				// We set the forwarding fee to 0 for now as we're getting paid by the channel fee.
				//
				// TODO: revisit this decision eventually.
				config.channel_config.forwarding_fee_base_msat = 0;
				config.channel_config.forwarding_fee_proportional_millionths = 0;

				let result = if service_config.disable_client_reserve {
					self.channel_manager.create_channel_to_trusted_peer_0reserve(
						their_network_key,
						channel_amount_sats,
						0,
						user_channel_id,
						None,
						Some(config),
					)
				} else {
					self.channel_manager.create_channel(
						their_network_key,
						channel_amount_sats,
						0,
						user_channel_id,
						None,
						Some(config),
					)
				};

				match result {
					Ok(_) => {},
					Err(e) => {
						let zero_reserve_string =
							if service_config.disable_client_reserve { "0reserve " } else { "" };
						log_error!(
							self.logger,
							"Failed to open LSPS2 {}channel to {}: {:?}",
							zero_reserve_string,
							their_network_key,
							e
						);
						// TODO: We fail the payment back here. Eventually we will need to remember
						// the pending requests and regularly retry opening the channel until we
						// succeed.
						self.fail_channel_open(&their_network_key, user_channel_id).await;
						return;
					},
				}
			},
		}
	}
}

#[cfg(test)]
mod opening_cost_tests {
	use bitcoin::FeeRate;

	use super::JitOpeningCost;

	/// Blocknil's provider (bitcoin-wallet docs/jit-pricing.md, #68): a 153 vB funding transaction
	/// and a 169 vB cooperative close, 1.5× headroom on the fee rate, LDK's 200-sat closing-fee
	/// margin, a 2,000-sat floor, and 1,000 sats left to the customer.
	const COST: JitOpeningCost = JitOpeningCost {
		open_vbytes: 153,
		close_vbytes: 169,
		feerate_headroom_ppm: 1_500_000,
		close_fee_margin_sats: 200,
		min_fee_floor_sats: 2_000,
		min_payment_over_fee_sats: 1_000,
	};

	fn sat_per_vb(rate: u64) -> FeeRate {
		FeeRate::from_sat_per_vb_u32(rate as u32)
	}

	#[test]
	fn the_floor_is_the_minimum_at_low_fee_rates() {
		// 322 vB × 3 × 1.5 + 200 = 1,649: under the floor.
		for rate in [1, 2, 3] {
			assert_eq!(COST.min_fee_msat(sat_per_vb(rate)), 2_000_000, "{rate} sat/vB");
			assert_eq!(COST.min_payment_size_msat(sat_per_vb(rate)), 3_000_000, "{rate} sat/vB");
		}
		// The relay floor, 253 sat/kW, is under it too.
		assert_eq!(COST.min_fee_msat(FeeRate::from_sat_per_kwu(253)), 2_000_000);
	}

	#[test]
	fn above_the_floor_the_minimum_is_the_open_and_the_close_at_the_fee_rate() {
		// 322 vB × r × 1.5 + 200: 4 → 2,132; 10 → 5,030; 50 → 24,350.
		assert_eq!(COST.min_fee_msat(sat_per_vb(4)), 2_132_000);
		assert_eq!(COST.min_fee_msat(sat_per_vb(10)), 5_030_000);
		assert_eq!(COST.min_payment_size_msat(sat_per_vb(10)), 6_030_000);
		assert_eq!(COST.min_fee_msat(sat_per_vb(50)), 24_350_000);
		assert_eq!(COST.min_payment_size_msat(sat_per_vb(50)), 25_350_000);
	}

	#[test]
	fn the_on_chain_part_is_rounded_up_to_the_sat() {
		// 1,288 WU × 1,001 sat/kW × 1.5 = 1,933.932 sats: 1,934, plus the 200 margin.
		assert_eq!(COST.min_fee_msat(FeeRate::from_sat_per_kwu(1_001)), 2_134_000);
	}

	#[test]
	fn no_headroom_prices_the_rate_as_it_is() {
		let plain = JitOpeningCost { feerate_headroom_ppm: 1_000_000, ..COST };
		// 322 × 10 + 200.
		assert_eq!(plain.min_fee_msat(sat_per_vb(10)), 3_420_000);
	}

	/// bLIP-52 wants `min_payment_size_msat <= max_payment_size_msat`. With the provider's
	/// 100,000-sat maximum, the minimum payment passes it just over 204 sat/vB (322 vB × r × 1.5 +
	/// 200 + 1,000). Over it no payment can pay for the open, so no offer is made: lowering the
	/// minimum to the maximum would open channels for less than they cost on chain.
	#[test]
	fn no_offer_when_the_minimum_payment_is_over_the_maximum() {
		let max = 100_000_000;
		assert_eq!(
			super::offered_minimums(Some(COST), 0, 0, max, sat_per_vb(204)),
			Some((98_732_000, 99_732_000))
		);
		assert_eq!(super::offered_minimums(Some(COST), 0, 0, max, sat_per_vb(205)), None);
		// The static minimums are held to the same rule.
		assert_eq!(super::offered_minimums(None, 1, max, max, sat_per_vb(1)), Some((1, max)));
		assert_eq!(super::offered_minimums(None, 1, max + 1, max, sat_per_vb(1)), None);
	}

	#[test]
	fn absurd_numbers_saturate_rather_than_overflow() {
		let huge = JitOpeningCost {
			open_vbytes: u64::MAX,
			close_vbytes: u64::MAX,
			feerate_headroom_ppm: u32::MAX,
			close_fee_margin_sats: u64::MAX,
			min_fee_floor_sats: u64::MAX,
			min_payment_over_fee_sats: u64::MAX,
		};
		assert_eq!(huge.min_fee_msat(FeeRate::from_sat_per_kwu(u64::MAX)), u64::MAX);
		assert_eq!(huge.min_payment_size_msat(FeeRate::from_sat_per_kwu(u64::MAX)), u64::MAX);
	}
}
