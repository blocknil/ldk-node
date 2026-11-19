// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.

//! Blocknil migration gate (patch-notes/ldk-0.3-migration-plan.md, phase 1): can a provider get a
//! splice it funded, locked at zero confirmations and not confirming because its fee is too low,
//! confirmed by a child that pays for it (CPFP)? rust-lightning 0.3 refuses to RBF a splice on a
//! channel that locks splices at zero confirmations, so CPFP is the only way out.
//!
//! A stuck splice is modelled with bitcoind's `-blockmintxfee`: blocks only take transactions
//! (or packages, by their ancestor fee rate) paying at least `BLOCK_MIN_SAT_VB`. The splice pays
//! `SPLICE_SAT_VB`, below it, and stays in the mempool however many blocks are mined; everything
//! the setup broadcasts pays `SETUP_SAT_VB`, above it.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::time::Duration;

use bitcoin::{Amount, FeeRate, OutPoint, Transaction, Txid};
use common::{
	distribute_funds_unconfirmed, generate_blocks_and_wait, premine_and_distribute_funds,
	random_config, setup_bitcoind_and_electrsd_with_args, setup_node, wait_for_tx, TestChainSource,
	TestNode,
};
use electrsd::corepc_node::Client as BitcoindClient;
use electrsd::electrum_client::ElectrumApi;
use electrsd::ElectrsD;
use ldk_node::{Event, UserChannelId};
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use serde_json::{json, Value};

/// Blocks take nothing paying less than this (`-blockmintxfee`).
const BLOCK_MIN_SAT_VB: u64 = 5;
const BLOCK_MIN_ARG: &str = "-blockmintxfee=0.00005";
/// The splice's fee rate: relayable (1 sat/vB minimum relay fee), but below `BLOCK_MIN_SAT_VB`.
const SPLICE_SAT_VB: u64 = 2;
/// Every setup transaction pays this, so it confirms. bitcoind's own wallet pays its
/// `-fallbackfee` of 10 sat/vB.
const SETUP_SAT_VB: u64 = 10;
/// The child's own fee rate, high enough for the package to clear `BLOCK_MIN_SAT_VB`.
const CPFP_SAT_VB: u64 = 30;

/// The provider's on-chain reserve for its anchor channel (ldk-node's default).
const ANCHOR_RESERVE_SATS: u64 = 25_000;
const CHANNEL_SATS: u64 = 100_000;
const SPLICE_IN_SATS: u64 = 300_000;
/// More than the channel could carry before the splice.
const PAYMENT_MSAT: u64 = 200_000_000;

async fn wait_for(node: &TestNode, what: &str, want: impl Fn(&Event) -> bool) -> Event {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
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

struct Setup {
	bitcoind: electrsd::corepc_node::Node,
	electrsd: ElectrsD,
	provider: TestNode,
	customer: TestNode,
	user_channel_id: UserChannelId,
}

/// The provider holds one coin of 1M sats and opens a 100k channel to the customer from it. The
/// provider locks its own splices at once; the customer locks splices it didn't fund at once.
/// The customer has no on-chain funds and trusts the provider with the anchor reserve, so the
/// channel is an anchor channel. The provider keeps an anchor reserve of `provider_reserve_sats`
/// for it.
async fn setup(provider_reserve_sats: u64) -> Setup {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd_with_args(&[BLOCK_MIN_ARG]);
	let chain_source = TestChainSource::Esplora(&electrsd);

	let mut provider_config = random_config();
	provider_config.node_config.outbound_splice_min_depth = Some(0);
	provider_config.node_config.anchor_channels_config.per_channel_reserve_sats =
		provider_reserve_sats;
	let provider = setup_node(&chain_source, provider_config);
	let mut customer_config = random_config();
	customer_config.node_config.inbound_splice_min_depth = Some(0);
	customer_config.node_config.anchor_channels_config.trusted_peers_no_reserve =
		vec![provider.node_id()];
	let customer = setup_node(&chain_source, customer_config);

	let provider_address = provider.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![provider_address],
		Amount::from_sat(1_000_000),
	)
	.await;
	provider.sync_wallets().unwrap();

	provider
		.open_channel(
			customer.node_id(),
			customer.listening_addresses().unwrap().first().unwrap().clone(),
			CHANNEL_SATS,
			None,
			Some(FeeRate::from_sat_per_vb(SETUP_SAT_VB).unwrap()),
			None,
		)
		.unwrap();
	let funding_txo = match wait_for(&provider, "the channel's funding", |e| {
		matches!(e, Event::ChannelPending { .. })
	})
	.await
	{
		Event::ChannelPending { funding_txo, .. } => funding_txo,
		_ => unreachable!(),
	};
	wait_for_tx(&electrsd.client, funding_txo.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	assert!(mempool_entry(&bitcoind.client, &funding_txo.txid).is_none(), "the open confirmed");
	provider.sync_wallets().unwrap();
	customer.sync_wallets().unwrap();
	let user_channel_id =
		match wait_for(&provider, "the channel", |e| matches!(e, Event::ChannelReady { .. })).await
		{
			Event::ChannelReady { user_channel_id, .. } => user_channel_id,
			_ => unreachable!(),
		};
	wait_for(&customer, "the channel", |e| matches!(e, Event::ChannelReady { .. })).await;

	Setup { bitcoind, electrsd, provider, customer, user_channel_id }
}

/// The splice's funding outpoint, once both sides have negotiated it and it is in the mempool.
async fn negotiated_splice(s: &Setup) -> OutPoint {
	let splice_txo =
		match wait_for(&s.provider, "the splice", |e| matches!(e, Event::SpliceNegotiated { .. }))
			.await
		{
			Event::SpliceNegotiated { new_funding_txo, .. } => new_funding_txo,
			_ => unreachable!(),
		};
	wait_for_tx(&s.electrsd.client, splice_txo.txid).await;
	splice_txo
}

/// bitcoind's mempool entry for `txid`, or `None` once it left the mempool.
fn mempool_entry(bitcoind: &BitcoindClient, txid: &Txid) -> Option<Value> {
	bitcoind.call::<Value>("getmempoolentry", &[json!(txid.to_string())]).ok()
}

fn sats(btc: &Value) -> u64 {
	Amount::from_btc(btc.as_f64().unwrap()).unwrap().to_sat()
}

/// The txids of the chain tip's block.
fn tip_block_txids(bitcoind: &BitcoindClient) -> Vec<Txid> {
	let hash = bitcoind.call::<Value>("getbestblockhash", &[]).unwrap();
	let block = bitcoind.call::<Value>("getblock", &[hash, json!(1)]).unwrap();
	block["tx"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().parse().unwrap()).collect()
}

/// Mines `blocks` blocks and checks the splice is still unconfirmed in the mempool after each.
async fn assert_stuck(s: &Setup, splice_txid: &Txid, blocks: usize) {
	for _ in 0..blocks {
		generate_blocks_and_wait(&s.bitcoind.client, &s.electrsd.client, 1).await;
		assert!(!tip_block_txids(&s.bitcoind.client).contains(splice_txid));
		assert!(
			mempool_entry(&s.bitcoind.client, splice_txid).is_some(),
			"the splice stays in the mempool, unconfirmed"
		);
	}
}

fn fee_rate_sat_vb(entry: &Value) -> f64 {
	sats(&entry["fees"]["base"]) as f64 / entry["vsize"].as_u64().unwrap() as f64
}

/// The package fee rate miners see for `entry`: its fee and size together with its unconfirmed
/// ancestors'.
fn ancestor_fee_rate_sat_vb(entry: &Value) -> f64 {
	sats(&entry["fees"]["ancestor"]) as f64 / entry["ancestorsize"].as_u64().unwrap() as f64
}

fn splice_tx(s: &Setup, txid: &Txid) -> Transaction {
	s.electrsd.client.transaction_get(txid).unwrap()
}

/// The provider splices 300k in at 2 sat/vB from its coin-selected wallet. The splice locks at
/// zero confirmations and a payment larger than the old channel goes through on it. Blocks don't
/// take it. The splice has a change output back to the provider's wallet; the provider's
/// existing `send_all_to_address` (to its own address, at 30 sat/vB) spends that unconfirmed
/// change, and the next block confirms the splice together with the child.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn stuck_zero_conf_splice_confirms_by_cpfp_of_its_change() {
	let s = setup(ANCHOR_RESERVE_SATS).await;
	let channel = s.provider.list_channels().into_iter().next().unwrap();
	assert!(channel.channel_type.unwrap().requires_anchors_zero_fee_htlc_tx());

	s.provider
		.splice_in(
			&s.user_channel_id,
			s.customer.node_id(),
			SPLICE_IN_SATS,
			Some(FeeRate::from_sat_per_vb(SPLICE_SAT_VB).unwrap()),
		)
		.unwrap();
	let splice_txo = negotiated_splice(&s).await;
	let splice_txid = splice_txo.txid;

	// The splice locks with no confirmation on both sides.
	let is_spliced_ready = move |e: &Event| matches!(e, Event::ChannelReady { funding_txo: Some(txo), .. } if *txo == splice_txo);
	wait_for(&s.provider, "the splice to lock", is_spliced_ready).await;
	wait_for(&s.customer, "the splice to lock", is_spliced_ready).await;

	// It pays SPLICE_SAT_VB, less than blocks take.
	let splice_entry = mempool_entry(&s.bitcoind.client, &splice_txid).unwrap();
	let splice_rate = fee_rate_sat_vb(&splice_entry);
	println!("splice {}: {:?}", splice_txid, splice_entry);
	assert!(splice_rate >= 1.0 && splice_rate < BLOCK_MIN_SAT_VB as f64, "{}", splice_rate);

	// A payment the old channel could not carry goes through on the unconfirmed splice.
	let description =
		Bolt11InvoiceDescription::Direct(Description::new("cpfp gate".to_string()).unwrap());
	let invoice = s.customer.bolt11_payment().receive(PAYMENT_MSAT, &description, 3600).unwrap();
	s.provider.bolt11_payment().send(&invoice, None).unwrap();
	wait_for(
		&s.customer,
		"the payment",
		|e| matches!(e, Event::PaymentReceived { amount_msat, .. } if *amount_msat == PAYMENT_MSAT),
	)
	.await;
	wait_for(&s.provider, "the payment's success", |e| {
		matches!(e, Event::PaymentSuccessful { .. })
	})
	.await;

	// Stuck: blocks are mined, the splice stays in the mempool.
	assert_stuck(&s, &splice_txid, 3).await;

	// The splice has one output besides the new funding output: the provider's change.
	let splice = splice_tx(&s, &splice_txid);
	println!("splice outputs: {:?}", splice.output);
	assert_eq!(splice.output.len(), 2);
	// BDK lets a version 2 child spend only unconfirmed version 2 outputs (BIP 431); LDK builds
	// every splice as version 2.
	assert_eq!(splice.version, bitcoin::transaction::Version::TWO);
	let change_vout = if splice_txo.vout == 0 { 1 } else { 0 };
	let change = OutPoint { txid: splice_txid, vout: change_vout };
	let change_value = splice.output[change_vout as usize].value.to_sat();

	// The provider's wallet counts the unconfirmed change as spendable.
	s.provider.sync_wallets().unwrap();
	let balances = s.provider.list_balances();
	println!("provider balances before CPFP: {:?}", balances);
	assert_eq!(balances.total_onchain_balance_sats, change_value);
	assert_eq!(balances.total_anchor_channels_reserve_sats, ANCHOR_RESERVE_SATS);
	assert_eq!(balances.spendable_onchain_balance_sats, change_value - ANCHOR_RESERVE_SATS);

	// CPFP with the wallet as it is: send everything spendable back to ourselves at a high rate.
	let own_address = s.provider.onchain_payment().new_address().unwrap();
	let child_txid = s
		.provider
		.onchain_payment()
		.send_all_to_address(
			&own_address,
			true,
			Some(FeeRate::from_sat_per_vb(CPFP_SAT_VB).unwrap()),
		)
		.unwrap();
	wait_for_tx(&s.electrsd.client, child_txid).await;
	let child = splice_tx(&s, &child_txid);
	assert!(
		child.input.iter().any(|txin| txin.previous_output == change),
		"the child spends the splice's change"
	);

	// Miners now see the package at a rate blocks take.
	let child_entry = mempool_entry(&s.bitcoind.client, &child_txid).unwrap();
	println!("child {}: {:?}", child_txid, child_entry);
	assert_eq!(child_entry["ancestorcount"].as_u64().unwrap(), 2);
	let package_rate = ancestor_fee_rate_sat_vb(&child_entry);
	println!(
		"splice {:.2} sat/vB, child {:.2} sat/vB, package {:.2} sat/vB",
		splice_rate,
		fee_rate_sat_vb(&child_entry),
		package_rate
	);
	assert!(package_rate >= BLOCK_MIN_SAT_VB as f64);

	// The next block confirms the splice together with the child.
	generate_blocks_and_wait(&s.bitcoind.client, &s.electrsd.client, 1).await;
	let block = tip_block_txids(&s.bitcoind.client);
	assert!(block.contains(&splice_txid), "the splice confirmed");
	assert!(block.contains(&child_txid), "with its child");
	assert!(mempool_entry(&s.bitcoind.client, &splice_txid).is_none());

	// Both nodes see it.
	s.provider.sync_wallets().unwrap();
	s.customer.sync_wallets().unwrap();
	for node in [&s.provider, &s.customer] {
		let channel = node.list_channels().into_iter().next().unwrap();
		assert_eq!(channel.funding_txo, Some(splice_txo));
		assert_eq!(channel.confirmations, Some(1));
	}

	s.provider.stop().unwrap();
	s.customer.stop().unwrap();
}

/// The same stuck splice, but with no output to the provider's wallet: a splice of all its
/// confirmed coins by a provider that keeps no anchor reserve (`splice_in_with_all` otherwise
/// keeps the reserve as an output of its own). The provider's wallet can still send (it gets
/// a new coin), but nothing it sends spends the splice, so it stays stuck.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn stuck_splice_without_change_cannot_be_cpfped_by_the_wallet() {
	let s = setup(0).await;

	s.provider
		.splice_in_with_all(
			&s.user_channel_id,
			s.customer.node_id(),
			Some(FeeRate::from_sat_per_vb(SPLICE_SAT_VB).unwrap()),
		)
		.unwrap();
	let splice_txo = negotiated_splice(&s).await;
	let splice_txid = splice_txo.txid;
	let splice = splice_tx(&s, &splice_txid);
	println!("splice outputs: {:?}", splice.output);
	assert_eq!(splice.output.len(), 1, "only the new funding output");
	let splice_entry = mempool_entry(&s.bitcoind.client, &splice_txid).unwrap();
	assert!(fee_rate_sat_vb(&splice_entry) < BLOCK_MIN_SAT_VB as f64);

	// With nothing left on-chain, the wallet can't send at all.
	s.provider.sync_wallets().unwrap();
	assert_eq!(s.provider.list_balances().total_onchain_balance_sats, 0);
	let own_address = s.provider.onchain_payment().new_address().unwrap();
	let cpfp_rate = Some(FeeRate::from_sat_per_vb(CPFP_SAT_VB).unwrap());
	assert!(s
		.provider
		.onchain_payment()
		.send_all_to_address(&own_address, true, cpfp_rate)
		.is_err());

	// A new coin arrives and confirms; the splice doesn't.
	let coin_address = s.provider.onchain_payment().new_address().unwrap();
	distribute_funds_unconfirmed(
		&s.bitcoind.client,
		&s.electrsd.client,
		vec![coin_address],
		Amount::from_sat(100_000),
	)
	.await;
	assert_stuck(&s, &splice_txid, 1).await;

	// The wallet sends, but the child spends only the new coin: no CPFP of the splice.
	s.provider.sync_wallets().unwrap();
	let child_txid =
		s.provider.onchain_payment().send_all_to_address(&own_address, true, cpfp_rate).unwrap();
	wait_for_tx(&s.electrsd.client, child_txid).await;
	let child = splice_tx(&s, &child_txid);
	assert!(child.input.iter().all(|txin| txin.previous_output.txid != splice_txid));
	let child_entry = mempool_entry(&s.bitcoind.client, &child_txid).unwrap();
	assert_eq!(child_entry["ancestorcount"].as_u64().unwrap(), 1);

	generate_blocks_and_wait(&s.bitcoind.client, &s.electrsd.client, 1).await;
	let block = tip_block_txids(&s.bitcoind.client);
	assert!(block.contains(&child_txid), "the unrelated send confirmed");
	assert!(!block.contains(&splice_txid));
	assert!(mempool_entry(&s.bitcoind.client, &splice_txid).is_some(), "the splice is still stuck");

	s.provider.stop().unwrap();
	s.customer.stop().unwrap();
}
