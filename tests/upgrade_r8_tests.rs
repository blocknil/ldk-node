// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil: upgrading nodes in place from our ldk-node fork `blocknil-0.7.1-r8` (rust-lightning
//! 0.2.8 plus our patches) to this crate (ldk-node main on rust-lightning v0.3), with open
//! channels and no closing.
//!
//! # What it proves
//!
//! Three r8 nodes on regtest, payer -> provider -> customer, as our app uses them: the provider
//! runs LSPS2 with `disable_client_reserve`, its channel to the customer is a just-in-time channel
//! (zero reserve for the customer, anchors, private); the customer trusts the provider for
//! zero-conf and for no anchor reserve; the payer has a private anchor channel to the provider.
//! The r8 nodes make payments both ways, a confirmed splice-in on the customer's channel, a hold
//! SCID (`blocknil/hold_scids`) and a provider fee allowance (`blocknil/provider_fee_allowances`).
//! They stop, and this crate's nodes start on the same storage and seeds. Then:
//!
//! - the node ids are the same (the provider from its BIP 39 phrase, the others from 64 seed
//!   bytes, as the provider and the wallet derive theirs);
//! - before the new nodes start, their channels, balances and payments are exactly what the r8
//!   nodes reported last ([`NodeSnapshot`]; what can't be compared exactly is listed there);
//! - after they start and sync, the channels and the on-chain balance are still the same;
//! - the upgraded nodes pay both ways, splice in again, and close the customer's channel
//!   cooperatively, paying the customer exactly the balance its payments add up to;
//! - both `blocknil/*` keys are still in the store, byte for byte, after the new nodes ran.
//!
//! The `_in_flight` variant upgrades with a payment from the payer claimable at the customer but
//! not claimed: its HTLCs are on both channels during the upgrade, and the upgraded customer
//! claims it.
//!
//! # What it doesn't prove
//!
//! - Only the SQLite store by default (the wallet's local store); VSS (production for the provider
//!   and the wallet) runs with `--cfg vss_test` and a VSS server (below).
//! - None of r8's Blocknil behaviour after the upgrade: this crate has no hold SCIDs, so the key is
//!   only checked to survive; whether an old invoice whose route hint uses a hold SCID still pays
//!   after the upgrade is not tested (it presumably doesn't). The upgraded provider runs with this
//!   crate's defaults (`hold_private_forwards` off).
//! - No force close, no channel in the middle of a splice, no LSPS2 channel still opening, no
//!   payments to an offline customer held at the provider, no BOLT 12 or async payments.
//! - Esplora only; one regtest fee rate.
//!
//! # How to run
//!
//! ```sh
//! export BITCOIND_EXE=... ELECTRS_EXE=...  # as for the other integration tests
//! cargo test --test upgrade_r8_tests
//! # VSS: a running VSS server (noop authorizer) on Postgres.
//! TEST_VSS_BASE_URL=http://localhost:8080/vss RUSTFLAGS="--cfg vss_test" \
//!   cargo test --test upgrade_r8_tests r8_vss
//! ```
//!
//! The r8 crate is the `ldk-node-r8` dev-dependency (our fork at the r8 commit, from GitHub), on
//! our rust-lightning fork through the `[patch.crates-io]` in Cargo.toml. Each test takes about two
//! minutes.
//!
//! Each node logs to `ldk_node.log` in its storage directory, which the test prints; the r8 and the
//! upgraded node write to the same file.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint, Transaction};
use common::{
	generate_blocks_and_wait, generate_listening_addresses, premine_and_distribute_funds,
	random_storage_path, setup_bitcoind_and_electrsd, wait_for_tx,
};
use electrsd::electrum_client::ElectrumApi;
use ldk_node::config::{Config, EsploraSyncConfig};
use ldk_node::entropy::NodeEntropy;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::util::persist::KVStore;
use ldk_node::liquidity::LSPS2ServiceConfig;
use ldk_node::payment::{ConfirmationStatus, PaymentDirection, PaymentKind, PaymentStatus};
use ldk_node::{Builder, Event, LightningBalance, Node};
use ldk_node_r8 as r8;

const PAYER_SEED: [u8; 64] = [0x11; 64];
const CUSTOMER_SEED: [u8; 64] = [0x22; 64];
/// The provider's BIP 39 entropy (24 words), like the phrase in its seed file.
const PROVIDER_MNEMONIC_ENTROPY: [u8; 32] = [0x33; 32];

const PAYER_CHANNEL_SAT: u64 = 1_000_000;
/// The just-in-time payment that opens the customer's channel.
const JIT_PAYMENT_MSAT: u64 = 100_000_000;
const R8_PAY_CUSTOMER_MSAT: u64 = 20_000_000;
const R8_CUSTOMER_PAYS_MSAT: u64 = 5_000_000;
const R8_SPLICE_IN_SAT: u64 = 150_000;
const IN_FLIGHT_MSAT: u64 = 7_000_000;
const NEW_PAY_CUSTOMER_MSAT: u64 = 10_000_000;
const NEW_CUSTOMER_PAYS_MSAT: u64 = 3_000_000;
const NEW_SPLICE_IN_SAT: u64 = 100_000;
const CUSTOMER_ONCHAIN_SAT: u64 = 300_000;
const ALLOWANCE_FEE_MSAT: u64 = 1_234_000;
/// Each of a (keyed) anchor channel's two anchor outputs.
const ANCHOR_OUTPUT_SAT: u64 = 330;

// The provider's LSPS2 terms, as in production apart from the amounts: no reserve for the client,
// and the provider doesn't wait for the client's claim before broadcasting the funding.
const LSPS2_OPENING_FEE_PPM: u32 = 10_000;
const LSPS2_OVER_PROVISIONING_PPM: u32 = 1_000_000;
const LSPS2_MIN_OPENING_FEE_MSAT: u64 = 1_000;
const LSPS2_MIN_CHANNEL_LIFETIME: u32 = 100;
const LSPS2_MAX_CLIENT_TO_SELF_DELAY: u32 = 1024;
const LSPS2_MAX_PAYMENT_MSAT: u64 = 1_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn r8_sqlite_upgrade_keeps_channels_and_payments() {
	do_r8_upgrade(StoreKind::Sqlite, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn r8_sqlite_upgrade_with_payment_in_flight() {
	do_r8_upgrade(StoreKind::Sqlite, true).await;
}

#[cfg(vss_test)]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn r8_vss_upgrade_keeps_channels_and_payments() {
	let url = std::env::var("TEST_VSS_BASE_URL").expect("TEST_VSS_BASE_URL");
	do_r8_upgrade(StoreKind::Vss { url, prefix: random_suffix() }, false).await;
}

#[derive(Clone)]
enum StoreKind {
	Sqlite,
	/// Each node's store id is `prefix` plus its name.
	#[allow(dead_code)]
	Vss {
		url: String,
		prefix: String,
	},
}

#[derive(Clone)]
enum Entropy {
	Seed([u8; 64]),
	Mnemonic(String),
}

#[derive(Clone)]
enum Role {
	Payer,
	Provider,
	Customer { lsp: PublicKey, lsp_address: SocketAddress },
}

/// What a node is, kept across the upgrade.
#[derive(Clone)]
struct NodeSpec {
	name: &'static str,
	storage_dir: String,
	listening_addresses: Vec<SocketAddress>,
	entropy: Entropy,
	role: Role,
	store: StoreKind,
}

impl NodeSpec {
	fn new(name: &'static str, entropy: Entropy, role: Role, store: &StoreKind) -> Self {
		let storage_dir = random_storage_path().to_str().unwrap().to_owned();
		println!("{} stores in {} (log: {}/ldk_node.log)", name, storage_dir, storage_dir);
		NodeSpec {
			name,
			storage_dir,
			listening_addresses: generate_listening_addresses(),
			entropy,
			role,
			store: store.clone(),
		}
	}

	fn vss_store_id(&self) -> Option<(String, String)> {
		match &self.store {
			StoreKind::Sqlite => None,
			StoreKind::Vss { url, prefix } => {
				Some((url.clone(), format!("{}_{}", prefix, self.name)))
			},
		}
	}
}

async fn do_r8_upgrade(store: StoreKind, in_flight: bool) {
	let started = std::time::Instant::now();
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());

	let phrase =
		ldk_node::bip39::Mnemonic::from_entropy(&PROVIDER_MNEMONIC_ENTROPY).unwrap().to_string();
	let provider_spec =
		NodeSpec::new("provider", Entropy::Mnemonic(phrase), Role::Provider, &store);
	let payer_spec = NodeSpec::new("payer", Entropy::Seed(PAYER_SEED), Role::Payer, &store);

	// ---- The r8 nodes and their state. ----
	let provider = build_r8(&provider_spec, &esplora_url);
	let provider_id = provider.node_id();
	let customer_spec = NodeSpec::new(
		"customer",
		Entropy::Seed(CUSTOMER_SEED),
		Role::Customer {
			lsp: provider_id,
			lsp_address: provider_spec.listening_addresses[0].clone(),
		},
		&store,
	);
	let customer = build_r8(&customer_spec, &esplora_url);
	let payer = build_r8(&payer_spec, &esplora_url);
	let customer_id = customer.node_id();
	let payer_id = payer.node_id();

	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![
			payer.onchain_payment().new_address().unwrap(),
			provider.onchain_payment().new_address().unwrap(),
			provider.onchain_payment().new_address().unwrap(),
		],
		Amount::from_sat(2_000_000),
	)
	.await;
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![customer.onchain_payment().new_address().unwrap()],
		Amount::from_sat(CUSTOMER_ONCHAIN_SAT),
	)
	.await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}

	// The payer's private anchor channel to the provider.
	payer
		.open_channel(
			provider_id,
			to_r8_address(&provider_spec.listening_addresses[0]),
			PAYER_CHANNEL_SAT,
			None,
			None,
		)
		.unwrap();
	let funding = match r8_wait(&payer, "the payer's channel pending", |e| {
		matches!(e, r8::Event::ChannelPending { .. })
	})
	.await
	{
		r8::Event::ChannelPending { funding_txo, .. } => funding_txo,
		_ => unreachable!(),
	};
	wait_for_tx(&electrsd.client, funding.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	r8_wait(&payer, "the payer's channel ready", is_r8_channel_ready).await;
	r8_wait(&provider, "the payer's channel ready", is_r8_channel_ready).await;
	r8_wait_usable(&payer, provider_id).await;

	// The customer's channel: just in time, on its first payment, with no reserve for it.
	let mut customer_balance_msat = 0;
	let invoice = customer
		.bolt11_payment()
		.receive_via_jit_channel(JIT_PAYMENT_MSAT, &r8_description("jit"), 3600, None)
		.unwrap();
	payer.bolt11_payment().send(&invoice, None).unwrap();
	customer_balance_msat += r8_wait_received(&customer).await;
	r8_wait(&payer, "the JIT payment's success", is_r8_payment_successful).await;
	let opening_fee_msat = JIT_PAYMENT_MSAT - customer_balance_msat;
	assert_eq!(opening_fee_msat, JIT_PAYMENT_MSAT * LSPS2_OPENING_FEE_PPM as u64 / 1_000_000);
	let jit_funding = r8_channel(&provider, customer_id).funding_txo.unwrap();
	wait_for_tx(&electrsd.client, jit_funding.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	let customer_channel = r8_channel(&customer, provider_id);
	assert!(!customer_channel.is_outbound && !customer_channel.is_announced);
	assert_eq!(customer_channel.confirmations, Some(6));
	assert_eq!(customer_channel.unspendable_punishment_reserve, Some(0), "no customer reserve");
	let jit_channel_sat = customer_channel.channel_value_sats;
	r8_wait_usable(&provider, customer_id).await;
	r8_wait_usable(&customer, provider_id).await;

	// A payment each way over both channels.
	let invoice = customer
		.bolt11_payment()
		.receive(R8_PAY_CUSTOMER_MSAT, &r8_description("to customer"), 3600)
		.unwrap();
	payer.bolt11_payment().send(&invoice, None).unwrap();
	customer_balance_msat += r8_wait_received(&customer).await;
	r8_wait(&payer, "the payment's success", is_r8_payment_successful).await;

	let invoice = payer
		.bolt11_payment()
		.receive(R8_CUSTOMER_PAYS_MSAT, &r8_description("to payer"), 3600)
		.unwrap();
	customer.bolt11_payment().send(&invoice, None).unwrap();
	customer_balance_msat -= R8_CUSTOMER_PAYS_MSAT + r8_wait_fee_paid(&customer).await;
	r8_wait_received(&payer).await;

	// A splice-in of the provider's coins into the customer's channel, confirmed.
	let user_channel_id = r8_channel(&provider, customer_id).user_channel_id;
	provider.splice_in(&user_channel_id, customer_id, R8_SPLICE_IN_SAT).unwrap();
	let splice_txo = match r8_wait(&provider, "the splice pending", |e| {
		matches!(e, r8::Event::SplicePending { .. })
	})
	.await
	{
		r8::Event::SplicePending { new_funding_txo, .. } => new_funding_txo,
		_ => unreachable!(),
	};
	wait_for_tx(&electrsd.client, splice_txo.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	let splice_locked = |e: &r8::Event| matches!(e, r8::Event::ChannelReady { funding_txo: Some(txo), .. } if *txo == splice_txo);
	r8_wait(&provider, "the splice locked", splice_locked).await;
	r8_wait(&customer, "the splice locked", splice_locked).await;
	let customer_channel = r8_channel(&customer, provider_id);
	assert_eq!(customer_channel.channel_value_sats, jit_channel_sat + R8_SPLICE_IN_SAT);
	assert_eq!(customer_channel.funding_txo, Some(splice_txo));
	assert_eq!(customer_channel.unspendable_punishment_reserve, Some(0), "still no reserve");
	r8_wait_usable(&customer, provider_id).await;

	// Our two keys: a hold SCID at the provider, a fee allowance at the customer.
	let hold_scid = provider.hold_scid_for(customer_id).unwrap();
	customer.set_fee_provider(Some(provider_id));
	let allowance_hash = r8::lightning::types::payment::PaymentHash([0xab; 32]);
	customer.allow_provider_fee(allowance_hash, ALLOWANCE_FEE_MSAT).unwrap();
	let allowance = customer.provider_fee_allowances();
	assert_eq!(allowance.len(), 1);
	let expected_hold_scids = format!("{:016x} {}\n", hold_scid, customer_id).into_bytes();
	let expected_allowances =
		format!("{} {} {}\n", allowance_hash, ALLOWANCE_FEE_MSAT, allowance[0].given_at)
			.into_bytes();

	// Optionally, a payment claimable at the customer and not claimed, across the upgrade.
	let in_flight_preimage = [0x77; 32];
	let in_flight_hash = Sha256::hash(&in_flight_preimage).to_byte_array();
	if in_flight {
		let invoice = customer
			.bolt11_payment()
			.receive_for_hash(
				IN_FLIGHT_MSAT,
				&r8_description("in flight"),
				3600,
				r8::lightning::types::payment::PaymentHash(in_flight_hash),
			)
			.unwrap();
		payer.bolt11_payment().send(&invoice, None).unwrap();
		r8_wait(&customer, "the in-flight payment claimable", |e| {
			matches!(e, r8::Event::PaymentClaimable { claimable_amount_msat, .. }
				if *claimable_amount_msat == IN_FLIGHT_MSAT)
		})
		.await;
	}

	// The last state the r8 nodes report, with nothing left in their event queues.
	for node in [&payer, &provider, &customer] {
		r8_drain_events(node).await;
	}
	let before: Vec<NodeSnapshot> =
		[&payer, &provider, &customer].iter().map(|n| snapshot_r8(n)).collect();
	for snapshot in &before {
		println!("r8 {:#?}", snapshot);
	}
	if in_flight {
		let channel = r8_channel(&customer, provider_id);
		assert_eq!(channel.pending_inbound_htlc_count, 1, "the payment is in flight");
	}

	for node in [&payer, &provider, &customer] {
		node.stop().unwrap();
	}
	drop((payer, provider, customer));
	if matches!(store, StoreKind::Sqlite) {
		assert_eq!(read_r8_sqlite(&provider_spec, "hold_scids"), expected_hold_scids);
		assert_eq!(read_r8_sqlite(&customer_spec, "provider_fee_allowances"), expected_allowances);
	}

	// ---- The upgrade: this crate's nodes on the same storage and seeds. ----
	let payer = build_new(&payer_spec, &esplora_url);
	let provider = build_new(&provider_spec, &esplora_url);
	let customer = build_new(&customer_spec, &esplora_url);
	assert_eq!(payer.node_id(), payer_id);
	assert_eq!(provider.node_id(), provider_id);
	assert_eq!(customer.node_id(), customer_id);

	// Before they start: exactly the state the r8 nodes left.
	let after: Vec<NodeSnapshot> =
		[&payer, &provider, &customer].iter().map(|n| snapshot_new(n)).collect();
	for (b, a) in before.iter().zip(after.iter()) {
		assert_eq!(b, a, "{}'s state changed in the upgrade", b.name);
	}

	for node in [&payer, &provider, &customer] {
		node.start().unwrap();
	}
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	// Started and synced, with no new block: same channels, same coins. (Capacities may move once
	// the peers reconnect and agree a new commitment fee rate, so those aren't compared here.)
	for (b, node) in before.iter().zip([&payer, &provider, &customer]) {
		let a = snapshot_new(node);
		assert_eq!(b.stable(), a.stable(), "{} changed once started", b.name);
	}
	// As on r8, the customer keeps no on-chain anchor reserve for its provider's channel.
	assert_eq!(
		channel_with(&customer, provider_id).reserve_type,
		Some(ldk_node::ReserveType::TrustedPeersNoReserve)
	);
	assert_eq!(customer.list_balances().total_anchor_channels_reserve_sats, 0);

	wait_usable(&payer, provider_id).await;
	wait_usable(&provider, customer_id).await;
	wait_usable(&customer, provider_id).await;

	// ---- The upgraded nodes work. ----
	if in_flight {
		let payment_id = ldk_node::lightning::ln::channelmanager::PaymentId(in_flight_hash);
		customer
			.bolt11_payment()
			.claim_for_id(
				payment_id,
				ldk_node::lightning_types::payment::PaymentPreimage(in_flight_preimage),
			)
			.unwrap();
		let received_msat = wait_received(&customer).await;
		assert_eq!(received_msat, IN_FLIGHT_MSAT);
		customer_balance_msat += received_msat;
		wait(&payer, "the in-flight payment's success", is_payment_successful).await;
	}

	let invoice = customer
		.bolt11_payment()
		.receive(NEW_PAY_CUSTOMER_MSAT, &description("to customer, upgraded"), 3600)
		.unwrap();
	payer.bolt11_payment().send(&invoice, None).unwrap();
	customer_balance_msat += wait_received(&customer).await;
	wait(&payer, "the payment's success", is_payment_successful).await;

	let invoice = payer
		.bolt11_payment()
		.receive(NEW_CUSTOMER_PAYS_MSAT, &description("to payer, upgraded"), 3600)
		.unwrap();
	customer.bolt11_payment().send(&invoice, None).unwrap();
	customer_balance_msat -= NEW_CUSTOMER_PAYS_MSAT + wait_fee_paid(&customer).await;
	wait_received(&payer).await;

	// A new splice-in, confirmed.
	let channel = channel_with(&provider, customer_id);
	provider.splice_in(&channel.user_channel_id, customer_id, NEW_SPLICE_IN_SAT, None).unwrap();
	let splice_txo = match wait(&provider, "the new splice negotiated", |e| {
		matches!(e, Event::SpliceNegotiated { .. })
	})
	.await
	{
		Event::SpliceNegotiated { new_funding_txo, .. } => new_funding_txo,
		_ => unreachable!(),
	};
	wait_for_tx(&electrsd.client, splice_txo.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	let splice_locked = |e: &Event| matches!(e, Event::ChannelReady { funding_txo: Some(txo), .. } if *txo == splice_txo);
	wait(&provider, "the new splice locked", splice_locked).await;
	wait(&customer, "the new splice locked", splice_locked).await;
	let channel = channel_with(&customer, provider_id);
	// rust-lightning v0.3 puts what coin selection leaves over, when too little for a change output
	// (below P2WPKH's 294-sat dust limit), into the channel with the splice: a few sats more.
	let channel_value_sat = channel.channel_value_sats;
	let spliced_sat = channel_value_sat - (jit_channel_sat + R8_SPLICE_IN_SAT);
	assert!(
		(NEW_SPLICE_IN_SAT..NEW_SPLICE_IN_SAT + 294).contains(&spliced_sat),
		"spliced in {} sat",
		spliced_sat
	);
	assert_eq!(channel.funding_txo, Some(splice_txo));
	assert_eq!(channel.unspendable_punishment_reserve, Some(0), "still no customer reserve");
	wait_usable(&customer, provider_id).await;

	// The customer's balance in the channel is what its payments add up to.
	let customer_close_sat = claimable_on_close(&customer, channel.channel_id);
	assert_eq!(customer_close_sat, customer_balance_msat / 1000);

	// A cooperative close by the customer pays both sides from the last splice's output.
	let customer_onchain_before = customer.list_balances().total_onchain_balance_sats;
	let provider_onchain_before = provider.list_balances().total_onchain_balance_sats;
	customer.close_channel(&channel.user_channel_id, provider_id).unwrap();
	wait(&customer, "the channel closed", |e| matches!(e, Event::ChannelClosed { .. })).await;
	wait(&provider, "the channel closed", |e| matches!(e, Event::ChannelClosed { .. })).await;
	let closing_tx = spending_tx(&electrsd.client, splice_txo).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	let customer_received =
		customer.list_balances().total_onchain_balance_sats - customer_onchain_before;
	let provider_received =
		provider.list_balances().total_onchain_balance_sats - provider_onchain_before;
	let closing_fee =
		channel_value_sat - closing_tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
	println!(
		"closing tx {}: customer {} sat, provider {} sat, fee {} sat",
		closing_tx.compute_txid(),
		customer_received,
		provider_received,
		closing_fee
	);
	assert_eq!(closing_tx.output.len(), 2);
	assert_eq!(customer_received, customer_close_sat, "the customer gets its whole balance");
	assert_eq!(customer_received + provider_received + closing_fee, channel_value_sat);
	assert!(closing_fee > 0 && closing_fee < 5_000, "closing fee {}", closing_fee);
	assert!(customer.list_channels().is_empty());
	assert_eq!(provider.list_channels().len(), 1, "the payer's channel stays open");

	for node in [&payer, &provider, &customer] {
		node.stop().unwrap();
	}
	drop((payer, provider, customer));

	// Our two keys are still there after the upgraded nodes ran.
	assert_eq!(read_new(&provider_spec, "hold_scids").await, expected_hold_scids);
	assert_eq!(read_new(&customer_spec, "provider_fee_allowances").await, expected_allowances);
	println!("upgrade test took {:?}", started.elapsed());
}

// ---- Node state across versions. ----

/// What a node reports through its API, in types both versions share.
///
/// Compared exactly across the upgrade, before the new node starts. Left out, and why:
/// - `next_outbound_htlc_limit_msat` and the dust exposure: they depend on the fee estimator's
///   current rates, not only on the channel's state;
/// - r8's LSPS2 fee limits on a JIT payment (`PaymentKind::Bolt11Jit::lsp_fee_limits`): this
///   crate folds JIT payments into `PaymentKind::Bolt11` and keeps only the skimmed fee;
/// - an on-chain payment's `tx_type`, new in this crate.
///
/// And one value is translated: the opener's commitment fee in `ClaimableOnChannelClose`, which
/// r8 reports with the anchor outputs in it (see [`snapshot_r8`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeSnapshot {
	name: String,
	node_id: PublicKey,
	channels: Vec<ChannelSnapshot>,
	payments: Vec<PaymentSnapshot>,
	total_onchain_sat: u64,
	spendable_onchain_sat: u64,
	anchor_reserve_sat: u64,
	total_lightning_sat: u64,
	lightning_balances: Vec<String>,
	pending_sweeps: usize,
}

impl NodeSnapshot {
	/// What doesn't move once the node runs, with no new block: channels' identities, values and
	/// funding, the payments and the on-chain coins.
	fn stable(
		&self,
	) -> (Vec<(String, u64, Option<OutPoint>, Option<u64>)>, Vec<PaymentSnapshot>, u64) {
		let channels = self
			.channels
			.iter()
			.map(|c| {
				(
					format!("{} {} {}", c.channel_id, c.counterparty, c.user_channel_id),
					c.value_sat,
					c.funding_txo,
					c.short_channel_id,
				)
			})
			.collect();
		(channels, self.payments.clone(), self.total_onchain_sat)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelSnapshot {
	channel_id: String,
	user_channel_id: u128,
	counterparty: PublicKey,
	funding_txo: Option<OutPoint>,
	short_channel_id: Option<u64>,
	value_sat: u64,
	is_outbound: bool,
	is_announced: bool,
	is_channel_ready: bool,
	confirmations_required: Option<u32>,
	confirmations: Option<u32>,
	outbound_capacity_msat: u64,
	inbound_capacity_msat: u64,
	our_reserve_sat: Option<u64>,
	their_reserve_sat: u64,
	feerate_sat_per_kw: u32,
	force_close_spend_delay: Option<u16>,
	forwarding_fee_base_msat: u32,
	forwarding_fee_ppm: u32,
	cltv_expiry_delta: u16,
	inbound_htlc_minimum_msat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaymentSnapshot {
	id: String,
	/// The kind, with its hash, preimage, secret and skimmed fee, or txid and confirmation.
	kind: String,
	amount_msat: Option<u64>,
	fee_paid_msat: Option<u64>,
	outbound: bool,
	status: &'static str,
	latest_update_timestamp: u64,
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn opt_hex(bytes: Option<[u8; 32]>) -> String {
	bytes.map(|b| hex(&b)).unwrap_or_else(|| "-".to_string())
}

fn sorted<T, K: Ord>(mut items: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T> {
	items.sort_by_key(|i| key(i));
	items
}

fn snapshot_r8(node: &r8::Node) -> NodeSnapshot {
	let channels = node
		.list_channels()
		.into_iter()
		.map(|c| ChannelSnapshot {
			channel_id: hex(&c.channel_id.0),
			user_channel_id: c.user_channel_id.0,
			counterparty: c.counterparty_node_id,
			funding_txo: c.funding_txo,
			short_channel_id: c.short_channel_id,
			value_sat: c.channel_value_sats,
			is_outbound: c.is_outbound,
			is_announced: c.is_announced,
			is_channel_ready: c.is_channel_ready,
			confirmations_required: c.confirmations_required,
			confirmations: c.confirmations,
			outbound_capacity_msat: c.outbound_capacity_msat,
			inbound_capacity_msat: c.inbound_capacity_msat,
			our_reserve_sat: c.unspendable_punishment_reserve,
			their_reserve_sat: c.counterparty_unspendable_punishment_reserve,
			feerate_sat_per_kw: c.feerate_sat_per_1000_weight,
			force_close_spend_delay: c.force_close_spend_delay,
			forwarding_fee_base_msat: c.config.forwarding_fee_base_msat,
			forwarding_fee_ppm: c.config.forwarding_fee_proportional_millionths,
			cltv_expiry_delta: c.config.cltv_expiry_delta,
			inbound_htlc_minimum_msat: c.inbound_htlc_minimum_msat,
		})
		.collect::<Vec<_>>();
	let payments = node
		.list_payments()
		.into_iter()
		.map(|p| {
			use r8::payment::PaymentKind as K;
			let kind = match p.kind {
				K::Onchain { txid, status } => format!(
					"onchain {} {}",
					txid,
					match status {
						r8::payment::ConfirmationStatus::Confirmed {
							block_hash,
							height,
							timestamp,
						} => format!("confirmed {} {} {}", height, block_hash, timestamp),
						r8::payment::ConfirmationStatus::Unconfirmed => "unconfirmed".to_string(),
					}
				),
				K::Bolt11 { hash, preimage, secret } => format!(
					"bolt11 {} {} {} skimmed None",
					hex(&hash.0),
					opt_hex(preimage.map(|p| p.0)),
					opt_hex(secret.map(|s| s.0))
				),
				K::Bolt11Jit { hash, preimage, secret, counterparty_skimmed_fee_msat, .. } => {
					format!(
						"bolt11 {} {} {} skimmed {:?}",
						hex(&hash.0),
						opt_hex(preimage.map(|p| p.0)),
						opt_hex(secret.map(|s| s.0)),
						counterparty_skimmed_fee_msat
					)
				},
				other => panic!("the test makes no {:?}", other),
			};
			PaymentSnapshot {
				id: hex(&p.id.0),
				kind,
				amount_msat: p.amount_msat,
				fee_paid_msat: p.fee_paid_msat,
				outbound: p.direction == r8::payment::PaymentDirection::Outbound,
				status: match p.status {
					r8::payment::PaymentStatus::Pending => "pending",
					r8::payment::PaymentStatus::Succeeded => "succeeded",
					r8::payment::PaymentStatus::Failed => "failed",
				},
				latest_update_timestamp: p.latest_update_timestamp,
			}
		})
		.collect::<Vec<_>>();
	let balances = node.list_balances();
	let lightning_balances = balances
		.lightning_balances
		.iter()
		.map(|b| match b {
			r8::LightningBalance::ClaimableOnChannelClose {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				transaction_fee_satoshis,
				outbound_payment_htlc_rounded_msat,
				outbound_forwarded_htlc_rounded_msat,
				inbound_claiming_htlc_rounded_msat,
				inbound_htlc_rounded_msat,
			} => format!(
				"on close {} {} {} fee {} htlc rounding {} {} {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				// Our rust-lightning patch "count the opener's anchor outputs in a closed
				// channel's reported fee" adds the two anchor outputs to the opener's reported
				// commitment fee; v0.3 doesn't. Reporting only: the balance is the same.
				if *transaction_fee_satoshis > 0 {
					transaction_fee_satoshis - 2 * ANCHOR_OUTPUT_SAT
				} else {
					0
				},
				outbound_payment_htlc_rounded_msat,
				outbound_forwarded_htlc_rounded_msat,
				inbound_claiming_htlc_rounded_msat,
				inbound_htlc_rounded_msat
			),
			r8::LightningBalance::MaybePreimageClaimableHTLC {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				expiry_height,
				payment_hash,
			} => format!(
				"htlc in {} {} {} expiry {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				expiry_height,
				hex(&payment_hash.0)
			),
			r8::LightningBalance::MaybeTimeoutClaimableHTLC {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				claimable_height,
				payment_hash,
				outbound_payment,
			} => format!(
				"htlc out {} {} {} claimable {} {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				claimable_height,
				hex(&payment_hash.0),
				outbound_payment
			),
			other => panic!("unexpected balance {:?}", other),
		})
		.collect::<Vec<_>>();
	NodeSnapshot {
		name: node_name(node.node_id()),
		node_id: node.node_id(),
		channels: sorted(channels, |c| c.channel_id.clone()),
		payments: sorted(payments, |p| p.id.clone()),
		total_onchain_sat: balances.total_onchain_balance_sats,
		spendable_onchain_sat: balances.spendable_onchain_balance_sats,
		anchor_reserve_sat: balances.total_anchor_channels_reserve_sats,
		total_lightning_sat: balances.total_lightning_balance_sats,
		lightning_balances: {
			let mut l = lightning_balances;
			l.sort();
			l
		},
		pending_sweeps: balances.pending_balances_from_channel_closures.len(),
	}
}

fn snapshot_new(node: &Node) -> NodeSnapshot {
	let channels = node
		.list_channels()
		.into_iter()
		.map(|c| ChannelSnapshot {
			channel_id: hex(&c.channel_id.0),
			user_channel_id: c.user_channel_id.0,
			counterparty: c.counterparty.node_id,
			funding_txo: c.funding_txo,
			short_channel_id: c.short_channel_id,
			value_sat: c.channel_value_sats,
			is_outbound: c.is_outbound,
			is_announced: c.is_announced,
			is_channel_ready: c.is_channel_ready,
			confirmations_required: c.confirmations_required,
			confirmations: c.confirmations,
			outbound_capacity_msat: c.outbound_capacity_msat,
			inbound_capacity_msat: c.inbound_capacity_msat,
			our_reserve_sat: c.unspendable_punishment_reserve,
			their_reserve_sat: c.counterparty.unspendable_punishment_reserve,
			feerate_sat_per_kw: c.feerate_sat_per_1000_weight,
			force_close_spend_delay: c.force_close_spend_delay,
			forwarding_fee_base_msat: c.config.forwarding_fee_base_msat,
			forwarding_fee_ppm: c.config.forwarding_fee_proportional_millionths,
			cltv_expiry_delta: c.config.cltv_expiry_delta,
			inbound_htlc_minimum_msat: c.inbound_htlc_minimum_msat,
		})
		.collect::<Vec<_>>();
	let mut all_payments = Vec::new();
	let mut page_token = None;
	loop {
		let page = node.list_payments(page_token).unwrap();
		all_payments.extend(page.payments);
		match page.next_page_token {
			Some(token) => page_token = Some(token),
			None => break,
		}
	}
	let payments = all_payments
		.into_iter()
		.map(|p| {
			let kind = match p.kind {
				PaymentKind::Onchain { txid, status, .. } => format!(
					"onchain {} {}",
					txid,
					match status {
						ConfirmationStatus::Confirmed { block_hash, height, timestamp } =>
							format!("confirmed {} {} {}", height, block_hash, timestamp),
						ConfirmationStatus::Unconfirmed => "unconfirmed".to_string(),
					}
				),
				PaymentKind::Bolt11 { hash, preimage, secret, counterparty_skimmed_fee_msat } => {
					format!(
						"bolt11 {} {} {} skimmed {:?}",
						hex(&hash.0),
						opt_hex(preimage.map(|p| p.0)),
						opt_hex(secret.map(|s| s.0)),
						counterparty_skimmed_fee_msat
					)
				},
				other => panic!("the test makes no {:?}", other),
			};
			PaymentSnapshot {
				id: hex(&p.id.0),
				kind,
				amount_msat: p.amount_msat,
				fee_paid_msat: p.fee_paid_msat,
				outbound: p.direction == PaymentDirection::Outbound,
				status: match p.status {
					PaymentStatus::Pending => "pending",
					PaymentStatus::Succeeded => "succeeded",
					PaymentStatus::Failed => "failed",
				},
				latest_update_timestamp: p.latest_update_timestamp,
			}
		})
		.collect::<Vec<_>>();
	let balances = node.list_balances();
	let lightning_balances = balances
		.lightning_balances
		.iter()
		.map(|b| match b {
			LightningBalance::ClaimableOnChannelClose {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				transaction_fee_satoshis,
				outbound_payment_htlc_rounded_msat,
				outbound_forwarded_htlc_rounded_msat,
				inbound_claiming_htlc_rounded_msat,
				inbound_htlc_rounded_msat,
			} => format!(
				"on close {} {} {} fee {} htlc rounding {} {} {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				transaction_fee_satoshis,
				outbound_payment_htlc_rounded_msat,
				outbound_forwarded_htlc_rounded_msat,
				inbound_claiming_htlc_rounded_msat,
				inbound_htlc_rounded_msat
			),
			LightningBalance::MaybePreimageClaimableHTLC {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				expiry_height,
				payment_hash,
			} => format!(
				"htlc in {} {} {} expiry {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				expiry_height,
				hex(&payment_hash.0)
			),
			LightningBalance::MaybeTimeoutClaimableHTLC {
				channel_id,
				counterparty_node_id,
				amount_satoshis,
				claimable_height,
				payment_hash,
				outbound_payment,
			} => format!(
				"htlc out {} {} {} claimable {} {} {}",
				hex(&channel_id.0),
				counterparty_node_id,
				amount_satoshis,
				claimable_height,
				hex(&payment_hash.0),
				outbound_payment
			),
			other => panic!("unexpected balance {:?}", other),
		})
		.collect::<Vec<_>>();
	NodeSnapshot {
		name: node_name(node.node_id()),
		node_id: node.node_id(),
		channels: sorted(channels, |c| c.channel_id.clone()),
		payments: sorted(payments, |p| p.id.clone()),
		total_onchain_sat: balances.total_onchain_balance_sats,
		spendable_onchain_sat: balances.spendable_onchain_balance_sats,
		anchor_reserve_sat: balances.total_anchor_channels_reserve_sats,
		total_lightning_sat: balances.total_lightning_balance_sats,
		lightning_balances: {
			let mut l = lightning_balances;
			l.sort();
			l
		},
		pending_sweeps: balances.pending_balances_from_channel_closures.len(),
	}
}

fn node_name(node_id: PublicKey) -> String {
	node_id.to_string()[..8].to_string()
}

// ---- Building the nodes. ----

fn lsps2_terms_r8() -> r8::liquidity::LSPS2ServiceConfig {
	r8::liquidity::LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		channel_opening_fee_ppm: LSPS2_OPENING_FEE_PPM,
		channel_over_provisioning_ppm: LSPS2_OVER_PROVISIONING_PPM,
		min_channel_opening_fee_msat: LSPS2_MIN_OPENING_FEE_MSAT,
		min_channel_lifetime: LSPS2_MIN_CHANNEL_LIFETIME,
		max_client_to_self_delay: LSPS2_MAX_CLIENT_TO_SELF_DELAY,
		min_payment_size_msat: 0,
		max_payment_size_msat: LSPS2_MAX_PAYMENT_MSAT,
		client_trusts_lsp: false,
		disable_client_reserve: true,
	}
}

fn lsps2_terms() -> LSPS2ServiceConfig {
	LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		channel_opening_fee_ppm: LSPS2_OPENING_FEE_PPM,
		channel_over_provisioning_ppm: LSPS2_OVER_PROVISIONING_PPM,
		min_channel_opening_fee_msat: LSPS2_MIN_OPENING_FEE_MSAT,
		min_channel_lifetime: LSPS2_MIN_CHANNEL_LIFETIME,
		max_client_to_self_delay: LSPS2_MAX_CLIENT_TO_SELF_DELAY,
		min_payment_size_msat: 0,
		max_payment_size_msat: LSPS2_MAX_PAYMENT_MSAT,
		client_trusts_lsp: false,
		disable_client_reserve: true,
	}
}

/// Builds and starts the r8 node, configured as the wallet and the provider configure theirs
/// where it matters to the channels: anchors on, LSPS2 as above, the customer trusting its
/// provider for zero-conf (r8 does that for an LSPS2 source) and for no anchor reserve.
fn build_r8(spec: &NodeSpec, esplora_url: &str) -> r8::Node {
	let mut config = r8::config::Config::default();
	config.network = bitcoin::Network::Regtest;
	config.storage_dir_path = spec.storage_dir.clone();
	config.listening_addresses = Some(spec.listening_addresses.iter().map(to_r8_address).collect());
	assert!(config.anchor_channels_config.is_some(), "r8 opens anchor channels by default");

	let mut builder = r8::Builder::from_config(config);
	match &spec.entropy {
		Entropy::Seed(seed) => {
			builder.set_entropy_seed_bytes(*seed);
		},
		Entropy::Mnemonic(phrase) => {
			builder.set_entropy_bip39_mnemonic(r8::bip39::Mnemonic::parse(phrase).unwrap(), None);
		},
	}
	builder.set_chain_source_esplora(
		esplora_url.to_owned(),
		Some(r8::config::EsploraSyncConfig { background_sync_config: None }),
	);
	match &spec.role {
		Role::Payer => {},
		Role::Provider => {
			builder.set_liquidity_provider_lsps2(lsps2_terms_r8());
		},
		Role::Customer { lsp, lsp_address } => {
			builder.set_liquidity_source_lsps2(*lsp, to_r8_address(lsp_address), None);
			builder.add_trusted_peer_no_reserve(*lsp);
		},
	}
	let node = match spec.vss_store_id() {
		None => builder.build(),
		Some((url, store_id)) => {
			builder.build_with_vss_store_and_fixed_headers(url, store_id, HashMap::new())
		},
	}
	.unwrap_or_else(|e| panic!("r8 {} failed to build: {:?}", spec.name, e));
	node.start().unwrap();
	node
}

/// Builds this crate's node on `spec`'s storage, configured as [`build_r8`] does, not started.
fn build_new(spec: &NodeSpec, esplora_url: &str) -> Node {
	let mut config = Config::default();
	config.network = bitcoin::Network::Regtest;
	config.storage_dir_path = spec.storage_dir.clone();
	config.listening_addresses = Some(spec.listening_addresses.clone());
	if let Role::Customer { lsp, .. } = &spec.role {
		config.anchor_channels_config.trusted_peers_no_reserve.push(*lsp);
	}

	let mut builder = Builder::from_config(config);
	let mut sync_config = EsploraSyncConfig::default();
	sync_config.background_sync_config = None;
	builder.set_chain_source_esplora(esplora_url.to_owned(), Some(sync_config));
	match &spec.role {
		Role::Payer => {},
		Role::Provider => {
			builder.enable_liquidity_provider(lsps2_terms());
		},
		Role::Customer { lsp, lsp_address } => {
			builder.add_liquidity_source(*lsp, lsp_address.clone(), None, true);
		},
	}
	let entropy = match &spec.entropy {
		Entropy::Seed(seed) => NodeEntropy::from_seed_bytes(*seed),
		Entropy::Mnemonic(phrase) => NodeEntropy::from_bip39_mnemonic(
			ldk_node::bip39::Mnemonic::parse(phrase).unwrap(),
			None,
		),
	};
	match spec.vss_store_id() {
		None => builder.build(entropy),
		Some((url, store_id)) => {
			builder.build_with_vss_store_and_fixed_headers(entropy, url, store_id, HashMap::new())
		},
	}
	.unwrap_or_else(|e| {
		panic!(
			"upgraded {} failed to build: {:?} (see {}/ldk_node.log)",
			spec.name, e, spec.storage_dir
		)
	})
}

fn to_r8_address(address: &SocketAddress) -> r8::lightning::ln::msgs::SocketAddress {
	match address {
		SocketAddress::TcpIpV4 { addr, port } => {
			r8::lightning::ln::msgs::SocketAddress::TcpIpV4 { addr: *addr, port: *port }
		},
		_ => panic!("unexpected non-IPv4 test address: {:?}", address),
	}
}

#[cfg(vss_test)]
fn random_suffix() -> String {
	random_storage_path().file_name().unwrap().to_str().unwrap().to_owned()
}

// ---- The `blocknil/*` keys. ----

/// Reads one of our keys with r8's own SQLite store, the r8 node stopped.
fn read_r8_sqlite(spec: &NodeSpec, key: &str) -> Vec<u8> {
	use r8::io::sqlite_store::{SqliteStore, KV_TABLE_NAME, SQLITE_DB_FILE_NAME};
	use r8::lightning::util::persist::KVStoreSync;
	let store = SqliteStore::new(
		spec.storage_dir.clone().into(),
		Some(SQLITE_DB_FILE_NAME.to_string()),
		Some(KV_TABLE_NAME.to_string()),
	)
	.unwrap();
	KVStoreSync::read(&store, "blocknil", "", key).unwrap()
}

/// Reads one of our keys with this crate's store, the node stopped.
async fn read_new(spec: &NodeSpec, key: &str) -> Vec<u8> {
	match spec.vss_store_id() {
		None => {
			use ldk_node::io::sqlite_store::{SqliteStore, KV_TABLE_NAME, SQLITE_DB_FILE_NAME};
			let store = SqliteStore::new(
				spec.storage_dir.clone().into(),
				Some(SQLITE_DB_FILE_NAME.to_string()),
				Some(KV_TABLE_NAME.to_string()),
			)
			.unwrap();
			KVStore::read(&store, "blocknil", "", key).await.unwrap()
		},
		Some((url, store_id)) => {
			let entropy = match &spec.entropy {
				Entropy::Seed(seed) => NodeEntropy::from_seed_bytes(*seed),
				Entropy::Mnemonic(phrase) => NodeEntropy::from_bip39_mnemonic(
					ldk_node::bip39::Mnemonic::parse(phrase).unwrap(),
					None,
				),
			};
			let store = ldk_node::io::vss_store::VssStore::builder(
				entropy,
				url,
				store_id,
				bitcoin::Network::Regtest,
			)
			.build_with_fixed_headers(HashMap::new())
			.unwrap();
			KVStore::read(&store, "blocknil", "", key).await.unwrap()
		},
	}
}

// ---- Waiting on the r8 nodes. ----

const EVENT_TIMEOUT: Duration = Duration::from_secs(90);

/// Waits for the first event matching `want`, handling (and printing) the others.
async fn r8_wait(node: &r8::Node, what: &str, want: impl Fn(&r8::Event) -> bool) -> r8::Event {
	let deadline = tokio::time::Instant::now() + EVENT_TIMEOUT;
	loop {
		let event = tokio::time::timeout_at(deadline, node.next_event_async())
			.await
			.unwrap_or_else(|_| panic!("r8 {} timed out waiting for {}", node.node_id(), what));
		node.event_handled().unwrap();
		if want(&event) {
			println!("r8 {} got {:?}", node.node_id(), event);
			return event;
		}
		println!("r8 {} skipping {:?} while waiting for {}", node.node_id(), event, what);
	}
}

async fn r8_drain_events(node: &r8::Node) {
	while let Ok(event) =
		tokio::time::timeout(Duration::from_millis(500), node.next_event_async()).await
	{
		println!("r8 {} draining {:?}", node.node_id(), event);
		node.event_handled().unwrap();
	}
}

fn is_r8_channel_ready(e: &r8::Event) -> bool {
	matches!(e, r8::Event::ChannelReady { .. })
}

fn is_r8_payment_successful(e: &r8::Event) -> bool {
	matches!(e, r8::Event::PaymentSuccessful { .. })
}

/// The amount of the next payment `node` receives.
async fn r8_wait_received(node: &r8::Node) -> u64 {
	match r8_wait(node, "a payment", |e| matches!(e, r8::Event::PaymentReceived { .. })).await {
		r8::Event::PaymentReceived { amount_msat, .. } => amount_msat,
		_ => unreachable!(),
	}
}

/// The routing fee `node`'s next successful payment paid.
async fn r8_wait_fee_paid(node: &r8::Node) -> u64 {
	match r8_wait(node, "a payment's success", is_r8_payment_successful).await {
		r8::Event::PaymentSuccessful { fee_paid_msat, .. } => fee_paid_msat.unwrap(),
		_ => unreachable!(),
	}
}

fn r8_channel(node: &r8::Node, peer: PublicKey) -> r8::ChannelDetails {
	let mut channels: Vec<_> =
		node.list_channels().into_iter().filter(|c| c.counterparty_node_id == peer).collect();
	assert_eq!(channels.len(), 1, "one channel with {}", peer);
	channels.pop().unwrap()
}

async fn r8_wait_usable(node: &r8::Node, peer: PublicKey) {
	let deadline = tokio::time::Instant::now() + EVENT_TIMEOUT;
	while !node.list_channels().iter().any(|c| c.counterparty_node_id == peer && c.is_usable) {
		assert!(tokio::time::Instant::now() < deadline, "r8 channel with {} not usable", peer);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn r8_description(text: &str) -> r8::lightning_invoice::Bolt11InvoiceDescription {
	r8::lightning_invoice::Bolt11InvoiceDescription::Direct(
		r8::lightning_invoice::Description::new(text.to_string()).unwrap(),
	)
}

// ---- Waiting on the upgraded nodes. ----

async fn wait(node: &Node, what: &str, want: impl Fn(&Event) -> bool) -> Event {
	let deadline = tokio::time::Instant::now() + EVENT_TIMEOUT;
	loop {
		let event = tokio::time::timeout_at(deadline, node.next_event_async())
			.await
			.unwrap_or_else(|_| panic!("{} timed out waiting for {}", node.node_id(), what));
		node.event_handled().unwrap();
		if want(&event) {
			println!("{} got {:?}", node.node_id(), event);
			return event;
		}
		println!("{} skipping {:?} while waiting for {}", node.node_id(), event, what);
	}
}

fn is_payment_successful(e: &Event) -> bool {
	matches!(e, Event::PaymentSuccessful { .. })
}

async fn wait_received(node: &Node) -> u64 {
	match wait(node, "a payment", |e| matches!(e, Event::PaymentReceived { .. })).await {
		Event::PaymentReceived { amount_msat, .. } => amount_msat,
		_ => unreachable!(),
	}
}

async fn wait_fee_paid(node: &Node) -> u64 {
	match wait(node, "a payment's success", is_payment_successful).await {
		Event::PaymentSuccessful { fee_paid_msat, .. } => fee_paid_msat.unwrap(),
		_ => unreachable!(),
	}
}

fn channel_with(node: &Node, peer: PublicKey) -> ldk_node::ChannelDetails {
	let mut channels: Vec<_> =
		node.list_channels().into_iter().filter(|c| c.counterparty.node_id == peer).collect();
	assert_eq!(channels.len(), 1, "one channel with {}", peer);
	channels.pop().unwrap()
}

async fn wait_usable(node: &Node, peer: PublicKey) {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
	while !node.list_channels().iter().any(|c| c.counterparty.node_id == peer && c.is_usable) {
		assert!(
			tokio::time::Instant::now() < deadline,
			"{}'s channel with {} not usable after the upgrade",
			node.node_id(),
			peer
		);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn description(text: &str) -> ldk_node::lightning_invoice::Bolt11InvoiceDescription {
	ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
		ldk_node::lightning_invoice::Description::new(text.to_string()).unwrap(),
	)
}

fn claimable_on_close(node: &Node, channel_id: ldk_node::lightning::ln::types::ChannelId) -> u64 {
	let balances = node.list_balances();
	let amounts: Vec<u64> = balances
		.lightning_balances
		.iter()
		.filter_map(|b| match b {
			LightningBalance::ClaimableOnChannelClose {
				channel_id: id, amount_satoshis, ..
			} if *id == channel_id => Some(*amount_satoshis),
			_ => None,
		})
		.collect();
	assert_eq!(amounts.len(), 1, "{:?}", balances.lightning_balances);
	amounts[0]
}

/// The transaction that spends `outpoint`, once electrs has it.
async fn spending_tx<E: ElectrumApi>(electrs: &E, outpoint: OutPoint) -> Transaction {
	let funding_tx = electrs.transaction_get(&outpoint.txid).unwrap();
	let script = funding_tx.output[outpoint.vout as usize].script_pubkey.clone();
	for _ in 0..300 {
		for entry in electrs.script_get_history(&script).unwrap() {
			if entry.tx_hash == outpoint.txid {
				continue;
			}
			let tx = electrs.transaction_get(&entry.tx_hash).unwrap();
			if tx.input.iter().any(|i| i.previous_output == outpoint) {
				return tx;
			}
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	panic!("nothing spent {}", outpoint);
}
