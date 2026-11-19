// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: splice on arrival, the client side. Our provider may keep a fee out of a
//! payment it forwards to us, for room it spliced into our channel when the payment arrived, and
//! only on a payment we agreed a fee for: the wallet gives an allowance per payment hash after
//! agreeing to the provider's quote ([`crate::Node::allow_provider_fee`]). Upstream ldk-node
//! refuses any withheld fee unless the payment's own metadata carries LSPS2 limits; an allowance
//! is granted after the invoice was made, so it can't live there. It is checked when the payment
//! is claimable, spent when it is claimed, and lapses after a day.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;
use lightning::types::payment::PaymentHash;
use lightning::util::config::ChannelConfigUpdate;
use lightning::util::persist::KVStore;

use crate::held_payments::now_secs;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::types::{ChannelManager, DynStore};
use crate::Error;

/// Where r8 kept the allowances, and this code still does: one `payment_hash fee_msat given_at`
/// line per allowance (hex, decimal, decimal seconds since the Unix epoch), as r8 wrote them.
const NAMESPACE: &str = "blocknil";
const ALLOWANCES_KEY: &str = "provider_fee_allowances";

/// How long an allowance lasts when its payment never arrives: past any hold, and short enough
/// that the store stays small.
const ALLOWANCE_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// A fee our provider may keep out of one payment it forwards to us, for room it spliced into our
/// channel when the payment arrived. The wallet gives one per payment, after agreeing to the
/// provider's quote for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFeeAllowance {
	/// The payment it is for.
	pub payment_hash: PaymentHash,
	/// The most the provider may keep out of it, all parts together.
	pub fee_msat: u64,
	/// When it was given, in seconds since the Unix epoch. It lapses a day later.
	pub given_at: u64,
}

fn encode_allowances(allowances: &[ProviderFeeAllowance]) -> Vec<u8> {
	let mut out = String::new();
	for a in allowances {
		out.push_str(&format!("{} {} {}\n", a.payment_hash, a.fee_msat, a.given_at));
	}
	out.into_bytes()
}

fn decode_allowances(bytes: &[u8]) -> Vec<ProviderFeeAllowance> {
	String::from_utf8_lossy(bytes)
		.lines()
		.filter_map(|line| {
			let mut fields = line.split(' ');
			let hash = fields.next()?;
			let fee_msat = fields.next()?.parse().ok()?;
			let given_at = fields.next()?.parse().ok()?;
			if hash.len() != 64 {
				return None;
			}
			let mut payment_hash = [0u8; 32];
			for (i, byte) in payment_hash.iter_mut().enumerate() {
				*byte = u8::from_str_radix(hash.get(2 * i..2 * i + 2)?, 16).ok()?;
			}
			Some(ProviderFeeAllowance {
				payment_hash: PaymentHash(payment_hash),
				fee_msat,
				given_at,
			})
		})
		.collect()
}

fn lapsed(allowance: &ProviderFeeAllowance, now: u64) -> bool {
	now.saturating_sub(allowance.given_at) >= ALLOWANCE_LIFETIME.as_secs()
}

pub(crate) struct ProviderFees {
	/// The only peer that may keep a fee outside an LSPS2 just-in-time channel open.
	fee_provider: RwLock<Option<PublicKey>>,
	allowances: Mutex<Vec<ProviderFeeAllowance>>,
	kv_store: Arc<DynStore>,
	channel_manager: Arc<ChannelManager>,
	logger: Arc<Logger>,
}

impl ProviderFees {
	/// Reads the allowances r8 or an earlier run saved.
	pub(crate) async fn load(
		kv_store: Arc<DynStore>, channel_manager: Arc<ChannelManager>, logger: Arc<Logger>,
	) -> Result<Self, Error> {
		let allowances = match KVStore::read(&*kv_store, NAMESPACE, "", ALLOWANCES_KEY).await {
			Ok(bytes) => decode_allowances(&bytes),
			Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => Vec::new(),
			Err(e) => {
				log_error!(logger, "Failed to read provider fee allowances: {}", e);
				return Err(Error::PersistenceFailed);
			},
		};
		Ok(Self {
			fee_provider: RwLock::new(None),
			allowances: Mutex::new(allowances),
			kv_store,
			channel_manager,
			logger,
		})
	}

	pub(crate) fn fee_provider(&self) -> Option<PublicKey> {
		*self.fee_provider.read().expect("lock")
	}

	pub(crate) fn set_fee_provider(&self, provider: Option<PublicKey>) {
		*self.fee_provider.write().expect("lock") = provider;
		if let Some(provider) = provider {
			self.allow_underpaying_from(&provider);
		}
	}

	/// Sets `accept_underpaying_htlcs` on our channels with `peer` when it is our provider: a
	/// payment it kept a fee out of carries less than the payer sent, and LDK refuses that HTLC
	/// otherwise. The fee is still checked against the allowance before claiming.
	pub(crate) fn allow_underpaying_from(&self, peer: &PublicKey) {
		if self.fee_provider().as_ref() != Some(peer) {
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
		let update =
			ChannelConfigUpdate { accept_underpaying_htlcs: Some(true), ..Default::default() };
		if let Err(e) =
			self.channel_manager.update_partial_channel_config(peer, &channel_ids, &update)
		{
			log_error!(self.logger, "Failed to let our provider's channels carry its fee: {:?}", e);
		}
	}

	pub(crate) async fn allow(
		&self, payment_hash: PaymentHash, fee_msat: u64,
	) -> Result<(), Error> {
		let now = now_secs();
		let allowances = {
			let mut allowances = self.allowances.lock().expect("lock");
			allowances.retain(|a| a.payment_hash != payment_hash && !lapsed(a, now));
			allowances.push(ProviderFeeAllowance { payment_hash, fee_msat, given_at: now });
			allowances.clone()
		};
		self.save(&allowances).await?;
		log_info!(
			self.logger,
			"Our provider may keep up to {} msat of payment {}",
			fee_msat,
			payment_hash
		);
		Ok(())
	}

	/// The allowances given and not yet spent or lapsed.
	pub(crate) fn allowances(&self) -> Vec<ProviderFeeAllowance> {
		let now = now_secs();
		self.allowances.lock().expect("lock").iter().filter(|a| !lapsed(a, now)).copied().collect()
	}

	/// The payment was claimed: its allowance is spent.
	pub(crate) async fn used(&self, payment_hash: &PaymentHash) {
		let allowances = {
			let mut allowances = self.allowances.lock().expect("lock");
			let before = allowances.len();
			allowances.retain(|a| &a.payment_hash != payment_hash);
			if allowances.len() == before {
				return;
			}
			allowances.clone()
		};
		let _ = self.save(&allowances).await;
	}

	async fn save(&self, allowances: &[ProviderFeeAllowance]) -> Result<(), Error> {
		KVStore::write(
			&*self.kv_store,
			NAMESPACE,
			"",
			ALLOWANCES_KEY,
			encode_allowances(allowances),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Failed to save provider fee allowances: {}", e);
			Error::PersistenceFailed
		})
	}

	/// The most our provider may have kept out of the payment `payment_hash` that arrived over
	/// `receiving_channel_ids`: its allowance, when every one of those channels is with our
	/// provider. `None` otherwise.
	pub(crate) fn allowance_for(
		&self, receiving_channel_ids: &[(ChannelId, Option<u128>)], payment_hash: &PaymentHash,
	) -> Option<u64> {
		let provider = self.fee_provider()?;
		if receiving_channel_ids.is_empty() {
			return None;
		}
		let channels = self.channel_manager.list_channels_with_counterparty(&provider);
		let all_from_provider = receiving_channel_ids
			.iter()
			.all(|(id, _)| channels.iter().any(|c| &c.channel_id == id));
		if !all_from_provider {
			return None;
		}
		self.allowances().iter().find(|a| &a.payment_hash == payment_hash).map(|a| a.fee_msat)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn provider_fee_allowances_read_r8s_format() {
		// What r8 wrote (held_forwards.rs `encode_allowances`).
		let hash = "ab".repeat(32);
		let r8 = format!("{hash} 1234000 1790000000\n{} 0 1\n", "07".repeat(32));
		let allowances = decode_allowances(r8.as_bytes());
		assert_eq!(
			allowances,
			vec![
				ProviderFeeAllowance {
					payment_hash: PaymentHash([0xab; 32]),
					fee_msat: 1_234_000,
					given_at: 1_790_000_000,
				},
				ProviderFeeAllowance {
					payment_hash: PaymentHash([7; 32]),
					fee_msat: 0,
					given_at: 1
				},
			]
		);
		assert_eq!(encode_allowances(&allowances), r8.into_bytes());
		assert!(decode_allowances(b"garbage\nab 1 2\n").is_empty());
	}
}
