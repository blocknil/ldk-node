// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil: mixed versions on regtest. During the move to rust-lightning 0.3 the provider is
//! upgraded first, while TestFlight phones still run r8 (our ldk-node fork `blocknil-0.7.1-r8` on
//! rust-lightning `blocknil-0.2.8-r8`) and update at their own pace. These tests pair a provider of
//! this crate with an r8 customer, and (less) the reverse.
//!
//! Each node is configured the way its app configures it, where it matters to the peer:
//! - **new provider** (bitcoin-wallet `ldk03-port`, `core/provider/main.rs`): `hold_private_forwards`,
//!   `trust_own_splice_inputs_0conf`, LSPS2 with `disable_client_reserve` and the 2 h 15 min offer
//!   lifetime, LSPS5 service, inbound minimum depth 1, one channel per peer, forwarding at no fee
//!   with each channel's CLTV delta set to 144 (`wallet_core::forwarding`), async-payments server;
//! - **r8 customer** (bitcoin-wallet main, `core/src/lightning.rs`): LSPS2 source (which r8 also
//!   trusts for zero-conf channels and splices), LSPS5 client, no anchor reserve for the provider,
//!   onion messages via the provider, async-payments client, the provider as its fee provider; it
//!   doesn't listen, and dials the provider itself, as a phone does;
//! - **r8 provider / new customer** (reverse): r8's `core/provider/main.rs` and `ldk03-port`'s
//!   `core/src/lightning.rs`, the same way.
//!
//! The payer stands for the rest of the network: a node of this crate with a private channel to
//! the provider.
//!
//! What the app does above ldk-node is played by the test: the splice-on-arrival quote and answer
//! (`wallet_core::arrival` and `quote`) become a direct `allow_provider_fee` on the customer and
//! `set_held_payment_fee` plus `splice_in_with_change` on the provider, in the provider's order; the
//! provider's wake handler calls `notify_payment_incoming`, as `core/provider/main.rs` does; the
//! LSPS5 webhook sender records the POSTs instead of sending them to the relay.
//!
//! # What these tests don't cover
//!
//! - A new wallet with an r8 provider beyond a basic receive and send: the plan upgrades the
//!   provider first, so production never has that pair. What does and doesn't work there is in
//!   [`r8_provider_new_customer_receive_and_send`].
//! - BOLT 12 and async payments, the BIP 353 resolver, multi-part payments short of room.
//! - The splice-on-arrival HTTP quote protocol (`room.rs`), which is app code, not ldk-node.
//! - VSS: every node here stores in SQLite (storage plays no part between peers).
//!
//! # How to run
//!
//! ```sh
//! export BITCOIND_EXE=... ELECTRS_EXE=...  # as for the other integration tests
//! cargo test --test mixed_version_r8_tests -- --test-threads=1
//! ```
//!
//! The r8 crate is the `ldk-node-r8` dev-dependency (our fork at the r8 commit, from GitHub), on
//! our rust-lightning fork through the `[patch.crates-io]` in Cargo.toml. Each test takes one to
//! two minutes; each node logs to `ldk_node.log` in its storage directory, which the test prints.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::str::FromStr;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use common::{
	generate_blocks_and_wait, generate_listening_addresses, premine_and_distribute_funds,
	random_storage_path, setup_bitcoind_and_electrsd, wait_for_tx,
};
use electrsd::corepc_node::Node as BitcoinD;
use electrsd::ElectrsD;
use ldk_node::config::{AsyncPaymentsRole, Config, EsploraSyncConfig, HRNResolverConfig};
use ldk_node::entropy::NodeEntropy;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::liquidity::{LSPS2ServiceConfig, LSPS5ServiceConfig, WebhookPost};
use ldk_node::{Builder, Event, LightningBalance, Node, ShortOfRoom};
use ldk_node_r8 as r8;

/// The provider's forwarding CLTV delta (decision 1; `FORWARDING_CLTV_EXPIRY_DELTA`).
const CLTV_EXPIRY_DELTA: u16 = 144;
/// What the provider keeps on chain for each anchor channel with an untrusted peer (its default).
const ANCHOR_RESERVE_PER_CHANNEL_SAT: u64 = 5_000;

const PAYER_CHANNEL_SAT: u64 = 1_000_000;
/// The payment that opens the customer's channel just in time.
const JIT_PAYMENT_MSAT: u64 = 100_000_000;
const RECEIVE_MSAT: u64 = 20_000_000;
const SEND_MSAT: u64 = 5_000_000;
const HELD_MSAT: u64 = 30_000_000;
/// Larger than the customer's whole channel (about 198,000 sat after the JIT payment): it fits only
/// once room is spliced in, and only if both ends raised the channel's in-flight limit (rl-04).
const ARRIVAL_MSAT: u64 = 300_000_000;
const ARRIVAL_SPLICE_SAT: u64 = 300_000;
const ARRIVAL_FEE_MSAT: u64 = 1_000_000;

// The provider's LSPS2 terms: production's shape, test amounts.
const LSPS2_OPENING_FEE_PPM: u32 = 10_000;
const LSPS2_OVER_PROVISIONING_PPM: u32 = 1_000_000;
const LSPS2_MIN_OPENING_FEE_MSAT: u64 = 1_000;
const LSPS2_MIN_CHANNEL_LIFETIME: u32 = 100;
const LSPS2_MAX_CLIENT_TO_SELF_DELAY: u32 = 1024;
const LSPS2_MAX_PAYMENT_MSAT: u64 = 1_000_000_000;

/// The webhook an r8 phone registers: the relay's URL, which the provider's sender would POST to.
const WEBHOOK_URL: &str = "https://push.blocknil.test/v1/wake/abc123";
const WEBHOOK_APP_NAME: &str = "blocknil";
const PUSH_HOST: &str = "push.blocknil.test";

// ---- New provider, r8 customer: what production meets during the transition. ----

/// An r8 customer gets its first channel just in time from the new provider, as it does from an r8
/// one; then receives an ordinary invoice, and sends.
///
/// Proves across versions: LSPS2 (bLIP-52) between r8's client and 0.3's service, with the opening
/// fee r8 agreed to; the zero-reserve (`disable_client_reserve`), zero-conf JIT channel that 0.3
/// opens (`create_channel_to_trusted_peer_0reserve`) is accepted by r8's partial zero-reserve
/// backport (rl-07), anchors on both; ordinary forwards both ways, through a provider that
/// intercepts every forward to a private channel (`hold_private_forwards`); balances agree on both
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8_customer_opens_jit_receives_and_sends_with_new_provider() {
	let s = Forward::setup().await;

	let invoice = s
		.customer
		.bolt11_payment()
		.receive(RECEIVE_MSAT, &r8_description("ordinary"), 3600)
		.unwrap();
	s.payer.bolt11_payment().send(&from_r8(&invoice), None).unwrap();
	assert_eq!(r8_wait_received(&s.customer).await, RECEIVE_MSAT);
	wait(&s.payer, "the payment's success", is_payment_successful).await;

	let invoice = s.payer.bolt11_payment().receive(SEND_MSAT, &description("send"), 3600).unwrap();
	s.customer.bolt11_payment().send(&to_r8(&invoice), None).unwrap();
	let fee_msat = r8_wait_fee_paid(&s.customer).await;
	assert_eq!(fee_msat, 0, "the provider forwards its customers' payments at no fee");
	assert_eq!(wait_received(&s.payer).await, SEND_MSAT);

	// Both ends agree on the customer's balance.
	let customer_msat = s.jit_received_msat + RECEIVE_MSAT - SEND_MSAT;
	let channel = r8_channel(&s.customer, s.provider.node_id());
	assert_eq!(r8_claimable_on_close(&s.customer, channel.channel_id.0), customer_msat / 1000);
	let provider_side = channel_with(&s.provider, s.customer.node_id());
	assert_eq!(provider_side.inbound_capacity_msat, channel.outbound_capacity_msat);
	s.stop();
}

/// The r8 customer registers its webhook with the new provider (LSPS5), goes offline, and a
/// payment arrives for it: the provider holds it and POSTs `payment_incoming` to the webhook (the
/// push that wakes the phone); when the customer is back and dials the provider, the payment goes
/// out at once.
///
/// Proves across versions: LSPS5 (bLIP-55) registration from r8's client to 0.3's service, with
/// the answer reaching r8's result handler; the notification signed by the new provider for the
/// URL r8 registered; a payment to an offline r8 customer held by 0.3's interception
/// (`ToOfflinePrivateChannels`, the held-payments patch) rather than failed, and released on
/// reconnect after the channel is reestablished across versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_r8_customer_is_woken_over_lsps5_and_paid_on_reconnect() {
	let s = Forward::setup().await;
	let (customer_id, provider_id) = (s.customer.node_id(), s.provider.node_id());

	// Registration, as the r8 app does once the relay has issued a URL.
	let (results_tx, results) = mpsc::channel();
	let results_tx = Mutex::new(results_tx);
	s.customer.set_webhook_result_handler(Arc::new(move |r| {
		let _ = results_tx.lock().unwrap().send(r);
	}));
	s.customer
		.set_webhook(provider_id, WEBHOOK_APP_NAME.to_string(), WEBHOOK_URL.to_string())
		.unwrap();
	let result = block_recv(&results, Duration::from_secs(30)).await.expect("the provider answers");
	assert!(result.accepted, "registration refused: {}", result.error);
	assert_eq!(result.url, WEBHOOK_URL);
	assert_eq!(result.app_name, WEBHOOK_APP_NAME);
	let registered = next_post(&s.webhooks, "lsps5.webhook_registered").await;
	assert_eq!(registered.url, WEBHOOK_URL);

	// The phone goes to sleep with an invoice out.
	let invoice =
		s.customer.bolt11_payment().receive(HELD_MSAT, &r8_description("held"), 3600).unwrap();
	s.customer.stop().unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;

	s.payer.bolt11_payment().send(&from_r8(&invoice), None).unwrap();
	let held = Instant::now();
	while s.provider.held_payments().is_empty() {
		assert!(held.elapsed() < Duration::from_secs(30), "never held");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert_eq!(s.provider.held_payments()[0].0, customer_id);
	let wake = next_post(&s.webhooks, "lsps5.payment_incoming").await;
	assert_eq!(wake.url, WEBHOOK_URL, "the push goes to the URL the r8 phone registered");
	assert!(wake.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("x-lsps5-signature")));

	// The phone wakes, starts its node and dials its provider.
	s.customer.start().unwrap();
	let connected = Instant::now();
	s.customer.connect(provider_id, to_r8_address(&s.provider_address), true).unwrap();
	assert_eq!(r8_wait_received(&s.customer).await, HELD_MSAT);
	println!("the held payment reached the r8 customer {:?} after it dialled", connected.elapsed());
	wait(&s.payer, "the held payment's success", is_payment_successful).await;
	let record = &s.provider.recent_held_payments()[0];
	assert!(record.forwarded);
	assert_eq!(record.amount_msat, HELD_MSAT);
	assert!(s.provider.held_payments().is_empty());
	s.stop();
}

/// An r8 wallet with a channel makes its invoices through a hold SCID it asks its provider for.
/// The new provider keeps handing them out (decision 15) and honours them: a payment on one
/// reaches the r8 customer when it is online, and is held while it is offline.
///
/// Proves across versions: r8's `receive_via_hold_scid` invoice, built with the SCID from the new
/// provider's `hold_scid_for` and the CLTV delta the provider set on the channel, is paid through
/// 0.3's intercept-SCID path; the hold-SCID payment to an offline r8 customer is held and released
/// on reconnect as an ordinary one is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8_hold_scid_invoices_are_paid_through_new_provider() {
	let s = Forward::setup().await;
	let (customer_id, provider_id) = (s.customer.node_id(), s.provider.node_id());

	let scid = s.provider.hold_scid_for(customer_id).unwrap();
	assert_eq!(s.provider.hold_scid_for(customer_id).unwrap(), scid, "one per customer");
	let cltv_expiry_delta = channel_with(&s.provider, customer_id).config.cltv_expiry_delta;
	assert_eq!(cltv_expiry_delta, CLTV_EXPIRY_DELTA);
	let hold_invoice = |amount_msat| {
		s.customer
			.bolt11_payment()
			.receive_via_hold_scid(
				Some(amount_msat),
				&r8_description("hold scid"),
				3600,
				provider_id,
				scid,
				cltv_expiry_delta,
			)
			.unwrap()
	};

	// Online.
	let online = hold_invoice(RECEIVE_MSAT);
	assert_eq!(online.route_hints()[0].0[0].short_channel_id, scid);
	s.payer.bolt11_payment().send(&from_r8(&online), None).unwrap();
	assert_eq!(r8_wait_received(&s.customer).await, RECEIVE_MSAT);
	wait(&s.payer, "the hold-SCID payment's success", is_payment_successful).await;

	// Offline: held, and released when the phone dials back.
	let offline = hold_invoice(HELD_MSAT);
	s.customer.stop().unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;
	s.payer.bolt11_payment().send(&from_r8(&offline), None).unwrap();
	let held = Instant::now();
	while s.provider.held_payments().is_empty() {
		assert!(held.elapsed() < Duration::from_secs(30), "never held");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	s.customer.start().unwrap();
	s.customer.connect(provider_id, to_r8_address(&s.provider_address), true).unwrap();
	assert_eq!(r8_wait_received(&s.customer).await, HELD_MSAT);
	wait(&s.payer, "the held hold-SCID payment's success", is_payment_successful).await;
	assert!(s.provider.recent_held_payments().iter().any(|r| r.forwarded
		&& r.amount_msat == HELD_MSAT
		&& r.payment_hash.0 == offline.payment_hash().to_byte_array()));
	s.stop();
}

/// Splice on arrival for an r8 customer: a payment larger than its whole channel arrives on its
/// hold-SCID invoice; the new provider reports it short of room, the customer allows the quoted
/// fee (r8's `allow_provider_fee`), the provider splices its own coins in with
/// `splice_in_with_change` and lets the payment go less the fee. It is forwarded with no block
/// mined, and the r8 customer claims it, accepting the skimmed fee. The splice then confirms and
/// the channel keeps working.
///
/// Proves across versions: interactive splice negotiation between 0.3 (initiator) and r8
/// (acceptor); zero-conf splice locking, the provider through its per-channel
/// `outbound_splice_min_depth = 0` and r8 through `trusted_splice_peers_0conf` (rl-21), so both send
/// `splice_locked` at once; rl-04 on both ends (the payment is more than the channel's value before
/// the splice, so it fits only if both raised the in-flight limit with the splice); r8's fee
/// allowance check accepts a fee skimmed by 0.3 (`set_held_payment_fee`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn splice_on_arrival_for_r8_customer_without_a_block() {
	let s = Forward::setup().await;
	let (customer_id, provider_id) = (s.customer.node_id(), s.provider.node_id());
	let reports = short_of_room_reports(&s.provider);

	let before = r8_channel(&s.customer, provider_id);
	let before_sat = before.channel_value_sats;
	assert!(
		ARRIVAL_MSAT / 1000 > before_sat,
		"the payment ({} sat) must exceed the whole channel ({} sat) to test rl-04",
		ARRIVAL_MSAT / 1000,
		before_sat
	);
	let scid = s.provider.hold_scid_for(customer_id).unwrap();
	let invoice = s
		.customer
		.bolt11_payment()
		.receive_via_hold_scid(
			Some(ARRIVAL_MSAT),
			&r8_description("arrival"),
			3600,
			provider_id,
			scid,
			channel_with(&s.provider, customer_id).config.cltv_expiry_delta,
		)
		.unwrap();
	assert_eq!(invoice.route_hints()[0].0[0].htlc_maximum_msat, None, "uncapped, as r8 makes it");

	let height = s.height();
	s.payer.bolt11_payment().send(&from_r8(&invoice), None).unwrap();
	let short =
		block_recv(&reports, Duration::from_secs(30)).await.expect("reported short of room");
	assert_eq!(short.customer, customer_id);
	assert_eq!(short.amount_msat, ARRIVAL_MSAT);
	assert_eq!(short.payment_hash.0, invoice.payment_hash().to_byte_array());
	assert!(short.room_msat < short.amount_msat);

	// The wallet's answer to the quote, then the provider's: the fee first, then the splice.
	s.customer
		.allow_provider_fee(
			r8::lightning::types::payment::PaymentHash(short.payment_hash.0),
			ARRIVAL_FEE_MSAT,
		)
		.unwrap();
	s.provider.set_held_payment_fee(short.intercept_id, ARRIVAL_FEE_MSAT).unwrap();
	let ucid = channel_with(&s.provider, customer_id).user_channel_id;
	s.provider.splice_in_with_change(&ucid, customer_id, ARRIVAL_SPLICE_SAT, None).unwrap();

	// The r8 customer sees the splice lock (r8 re-signals it as `ChannelReady` with the new
	// funding), then the payment.
	let mut locked_on = None;
	let received_msat = loop {
		let event = r8_wait(&s.customer, "the splice lock and the payment", |e| {
			matches!(e, r8::Event::ChannelReady { .. } | r8::Event::PaymentReceived { .. })
		})
		.await;
		match event {
			r8::Event::ChannelReady { funding_txo, .. } => locked_on = funding_txo,
			r8::Event::PaymentReceived { amount_msat, .. } => break amount_msat,
			_ => unreachable!(),
		}
	};
	assert_eq!(received_msat, ARRIVAL_MSAT - ARRIVAL_FEE_MSAT);
	wait(&s.payer, "the large payment's success", is_payment_successful).await;
	assert_eq!(s.height(), height, "spliced, locked and forwarded with no block mined");
	assert!(s.customer.provider_fee_allowances().is_empty(), "the r8 allowance is spent");
	let record = &s.provider.recent_held_payments()[0];
	assert!(record.forwarded);
	assert_eq!(record.fee_msat, ARRIVAL_FEE_MSAT);

	// Both ends are on the splice: same funding, the new value, still no reserve for the customer.
	let after = r8_channel(&s.customer, provider_id);
	let provider_side = channel_with(&s.provider, customer_id);
	// `splice_in_with_change` puts the amount asked into the channel, give or take the BDK/LDK fee
	// rounding of the change it keeps (a sat here): a few sats more at most.
	let spliced_sat = after.channel_value_sats - before_sat;
	assert!(
		(ARRIVAL_SPLICE_SAT..ARRIVAL_SPLICE_SAT + 294).contains(&spliced_sat),
		"spliced in {} sat",
		spliced_sat
	);
	assert_eq!(provider_side.channel_value_sats, after.channel_value_sats);
	assert_eq!(provider_side.funding_txo, after.funding_txo);
	assert_ne!(after.funding_txo, before.funding_txo);
	assert_eq!(after.unspendable_punishment_reserve, Some(0));
	let splice_txo = after.funding_txo.unwrap();
	assert_eq!(provider_side.config.outbound_splice_min_depth, 0);
	assert_eq!(locked_on, Some(splice_txo), "the r8 customer locked the splice before the payment");
	let customer_msat = s.jit_received_msat + ARRIVAL_MSAT - ARRIVAL_FEE_MSAT;
	assert_eq!(r8_claimable_on_close(&s.customer, after.channel_id.0), customer_msat / 1000);

	// The splice confirms, and the channel keeps working both ways.
	wait_for_tx(&s.electrsd.client, splice_txo.txid).await;
	generate_blocks_and_wait(&s.bitcoind.client, &s.electrsd.client, 6).await;
	s.sync();
	let invoice = s
		.customer
		.bolt11_payment()
		.receive(RECEIVE_MSAT, &r8_description("after the splice"), 3600)
		.unwrap();
	s.payer.bolt11_payment().send(&from_r8(&invoice), None).unwrap();
	assert_eq!(r8_wait_received(&s.customer).await, RECEIVE_MSAT);
	let invoice = s.payer.bolt11_payment().receive(SEND_MSAT, &description("back"), 3600).unwrap();
	s.customer.bolt11_payment().send(&to_r8(&invoice), None).unwrap();
	assert_eq!(wait_received(&s.payer).await, SEND_MSAT);
	let confirmed = r8_channel(&s.customer, provider_id);
	assert_eq!(confirmed.funding_txo, Some(splice_txo));
	assert!(confirmed.confirmations.unwrap_or(0) >= 6, "{:?}", confirmed.confirmations);
	s.stop();
}

// ---- r8 provider, new customer: not expected in production. ----

/// A new wallet with an r8 provider. The plan upgrades the provider before any wallet, so
/// production never has this pair; it is here only as far as it is cheap, to show what a phone
/// that updated before its provider would meet (staging, say).
///
/// Works: a JIT channel for an invoice of at most about 49 minutes (below), a receive through the
/// provider (`receive_via_provider`, the new wallet's only invoice once it has a channel), a send.
///
/// Doesn't, by design of the versions, and asserted here so a change shows:
/// - **a JIT invoice of 3600 s (the app's) can't be made:** ldk-node main's LSPS2 client needs the
///   provider's offer to outlive the invoice by 10 minutes plus the request timeout, and r8's offers
///   last one hour (ldk-05; inventory finding 3);
/// - **a payment to the new wallet while it is offline fails at once:** r8 holds only payments on
///   hold SCIDs, and the new wallet never asks for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8_provider_new_customer_receive_and_send() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());

	let provider_address = generate_listening_addresses()[0].clone();
	let provider = build_r8_provider(&esplora_url, &provider_address);
	let provider_id = provider.node_id();
	let payer = build_payer(&esplora_url);
	let customer = build_new_customer(&esplora_url, provider_id, &provider_address);
	let customer_id = customer.node_id();

	fund(&bitcoind, &electrsd, &payer, &[provider.onchain_payment().new_address().unwrap()]).await;
	provider.sync_wallets().unwrap();
	payer.sync_wallets().unwrap();
	open_payer_channel(&bitcoind, &electrsd, &payer, provider_id, &provider_address, || {
		provider.sync_wallets().unwrap()
	})
	.await;
	r8_wait_usable(&provider, payer.node_id()).await;

	// The app's one-hour JIT invoice: no offer from r8 lasts long enough.
	let refused = customer.bolt11_payment().receive_via_jit_channel(
		JIT_PAYMENT_MSAT,
		&description("jit, one hour"),
		3600,
	);
	println!("a 3600 s JIT invoice from an r8 provider: {:?}", refused);
	assert!(refused.is_err(), "r8's one-hour offers can't back a one-hour invoice");

	// A shorter one works: LSPS2 between this crate's client and r8's service.
	let invoice = customer
		.bolt11_payment()
		.receive_via_jit_channel(JIT_PAYMENT_MSAT, &description("jit, 30 min"), 1800)
		.unwrap();
	payer.bolt11_payment().send(&invoice, None).unwrap();
	let jit_received_msat = wait_received(&customer).await;
	assert_eq!(
		jit_received_msat,
		JIT_PAYMENT_MSAT - JIT_PAYMENT_MSAT * LSPS2_OPENING_FEE_PPM as u64 / 1_000_000
	);
	wait(&payer, "the JIT payment's success", is_payment_successful).await;
	let jit_txo = r8_channel(&provider, customer_id).funding_txo.unwrap();
	wait_for_tx(&electrsd.client, jit_txo.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	provider.sync_wallets().unwrap();
	payer.sync_wallets().unwrap();
	customer.sync_wallets().unwrap();
	assert_eq!(channel_with(&customer, provider_id).unspendable_punishment_reserve, Some(0));
	wait_usable(&customer, provider_id).await;
	r8_wait_usable(&provider, customer_id).await;

	// Receive the way the new wallet does once it has a channel, then send.
	let invoice = receive_via_provider(&customer, provider_id, RECEIVE_MSAT).await;
	payer.bolt11_payment().send(&invoice, None).unwrap();
	assert_eq!(wait_received(&customer).await, RECEIVE_MSAT);
	wait(&payer, "the payment's success", is_payment_successful).await;
	let invoice = payer.bolt11_payment().receive(SEND_MSAT, &description("send"), 3600).unwrap();
	customer.bolt11_payment().send(&invoice, None).unwrap();
	assert_eq!(wait_fee_paid(&customer).await, 0);
	assert_eq!(wait_received(&payer).await, SEND_MSAT);
	let channel = channel_with(&customer, provider_id);
	assert_eq!(
		claimable_on_close(&customer, channel.channel_id.0),
		(jit_received_msat + RECEIVE_MSAT - SEND_MSAT) / 1000
	);

	// Offline: r8 doesn't hold it.
	let invoice = receive_via_provider(&customer, provider_id, HELD_MSAT).await;
	customer.stop().unwrap();
	for _ in 0..100 {
		if provider.list_peers().iter().all(|p| p.node_id != customer_id || !p.is_connected) {
			break;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let sent = Instant::now();
	payer.bolt11_payment().send(&invoice, None).unwrap();
	wait(&payer, "the payment's failure", |e| matches!(e, Event::PaymentFailed { .. })).await;
	assert!(sent.elapsed() < Duration::from_secs(20), "failed at once, not held");

	payer.stop().unwrap();
	provider.stop().unwrap();
}

// ---- Setup: new provider, r8 customer. ----

struct Forward {
	bitcoind: BitcoinD,
	electrsd: ElectrsD,
	payer: Node,
	provider: Arc<Node>,
	provider_address: SocketAddress,
	customer: r8::Node,
	/// What the customer received of the JIT payment (less the opening fee).
	jit_received_msat: u64,
	webhooks: mpsc::Receiver<WebhookPost>,
}

impl Forward {
	/// The new provider, a payer with a private channel to it, and an r8 customer whose channel
	/// the provider opened just in time for a first payment, confirmed and usable.
	async fn setup() -> Self {
		let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
		let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());

		let provider_address = generate_listening_addresses()[0].clone();
		let (provider, webhooks) = build_new_provider(&esplora_url, &provider_address);
		let provider_id = provider.node_id();
		let payer = build_payer(&esplora_url);
		let customer = build_r8_customer(&esplora_url, provider_id, &provider_address);
		let customer_id = customer.node_id();

		let provider_addresses: Vec<_> =
			(0..3).map(|_| provider.onchain_payment().new_address().unwrap()).collect();
		fund(&bitcoind, &electrsd, &payer, &provider_addresses).await;
		provider.sync_wallets().unwrap();
		payer.sync_wallets().unwrap();
		open_payer_channel(&bitcoind, &electrsd, &payer, provider_id, &provider_address, || {
			provider.sync_wallets().unwrap()
		})
		.await;
		wait_usable(&provider, payer.node_id()).await;

		// The first payment opens the customer's channel.
		let invoice = customer
			.bolt11_payment()
			.receive_via_jit_channel(JIT_PAYMENT_MSAT, &r8_description("jit"), 3600, None)
			.unwrap();
		payer.bolt11_payment().send(&from_r8(&invoice), None).unwrap();
		let jit_received_msat = r8_wait_received(&customer).await;
		assert_eq!(
			jit_received_msat,
			JIT_PAYMENT_MSAT - JIT_PAYMENT_MSAT * LSPS2_OPENING_FEE_PPM as u64 / 1_000_000,
			"r8 paid exactly the opening fee it agreed to"
		);
		wait(&payer, "the JIT payment's success", is_payment_successful).await;
		// What the provider does on `ChannelPending` (decision 12), and at start for older channels.
		apply_forwarding_policy(&provider);

		let jit_txo = channel_with(&provider, customer_id).funding_txo.unwrap();
		wait_for_tx(&electrsd.client, jit_txo.txid).await;
		generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
		for node in [&payer, &*provider] {
			node.sync_wallets().unwrap();
		}
		customer.sync_wallets().unwrap();
		let channel = r8_channel(&customer, provider_id);
		assert!(!channel.is_outbound && !channel.is_announced);
		assert_eq!(channel.unspendable_punishment_reserve, Some(0), "no reserve for the customer");
		let provider_side = channel_with(&provider, customer_id);
		assert_eq!(provider_side.counterparty.unspendable_punishment_reserve, 0);
		// The provider locks its own splices into it at zero confirmations, not the customer's.
		assert_eq!(provider_side.config.outbound_splice_min_depth, 0);
		r8_wait_usable(&customer, provider_id).await;
		wait_usable(&provider, customer_id).await;
		r8_drain_events(&customer).await;

		Forward {
			bitcoind,
			electrsd,
			payer,
			provider,
			provider_address,
			customer,
			jit_received_msat,
			webhooks,
		}
	}

	fn sync(&self) {
		self.payer.sync_wallets().unwrap();
		self.provider.sync_wallets().unwrap();
		self.customer.sync_wallets().unwrap();
	}

	fn height(&self) -> u64 {
		self.bitcoind.client.get_block_count().unwrap().0
	}

	fn stop(&self) {
		let _ = self.customer.stop();
		let _ = self.payer.stop();
		let _ = self.provider.stop();
	}
}

/// Premines, then gives the payer 2,000,000 sat and each of `provider_addresses` as much.
async fn fund(
	bitcoind: &BitcoinD, electrsd: &ElectrsD, payer: &Node, provider_addresses: &[bitcoin::Address],
) {
	let mut addresses = vec![payer.onchain_payment().new_address().unwrap()];
	addresses.extend(provider_addresses.iter().cloned());
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(2_000_000),
	)
	.await;
}

/// The payer's private channel to the provider, confirmed.
async fn open_payer_channel(
	bitcoind: &BitcoinD, electrsd: &ElectrsD, payer: &Node, provider: PublicKey,
	provider_address: &SocketAddress, sync_provider: impl Fn(),
) {
	payer
		.open_channel(provider, provider_address.clone(), PAYER_CHANNEL_SAT, None, None, None)
		.unwrap();
	let funding = match wait(payer, "the payer's channel pending", |e| {
		matches!(e, Event::ChannelPending { .. })
	})
	.await
	{
		Event::ChannelPending { funding_txo, .. } => funding_txo,
		_ => unreachable!(),
	};
	wait_for_tx(&electrsd.client, funding.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	payer.sync_wallets().unwrap();
	sync_provider();
	wait(payer, "the payer's channel ready", |e| matches!(e, Event::ChannelReady { .. })).await;
	wait_usable(payer, provider).await;
}

// ---- Building the nodes. ----

fn storage(name: &str) -> String {
	let dir = random_storage_path().to_str().unwrap().to_owned();
	println!("{} stores in {} (log: {}/ldk_node.log)", name, dir, dir);
	dir
}

fn esplora_without_background_sync() -> EsploraSyncConfig {
	let mut sync = EsploraSyncConfig::default();
	sync.background_sync_config = None;
	sync
}

fn lsps2_terms() -> LSPS2ServiceConfig {
	LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		client_trusts_lsp: false,
		disable_client_reserve: true,
		channel_opening_fee_ppm: LSPS2_OPENING_FEE_PPM,
		channel_over_provisioning_ppm: LSPS2_OVER_PROVISIONING_PPM,
		min_channel_opening_fee_msat: LSPS2_MIN_OPENING_FEE_MSAT,
		min_channel_lifetime: LSPS2_MIN_CHANNEL_LIFETIME,
		max_client_to_self_delay: LSPS2_MAX_CLIENT_TO_SELF_DELAY,
		min_payment_size_msat: 0,
		max_payment_size_msat: LSPS2_MAX_PAYMENT_MSAT,
		opening_fee_params_lifetime_secs:
			ldk_node::liquidity::SHORT_OPENING_FEE_PARAMS_LIFETIME_SECS,
	}
}

fn lsps2_terms_r8() -> r8::liquidity::LSPS2ServiceConfig {
	r8::liquidity::LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		client_trusts_lsp: false,
		disable_client_reserve: true,
		channel_opening_fee_ppm: LSPS2_OPENING_FEE_PPM,
		channel_over_provisioning_ppm: LSPS2_OVER_PROVISIONING_PPM,
		min_channel_opening_fee_msat: LSPS2_MIN_OPENING_FEE_MSAT,
		min_channel_lifetime: LSPS2_MIN_CHANNEL_LIFETIME,
		max_client_to_self_delay: LSPS2_MAX_CLIENT_TO_SELF_DELAY,
		min_payment_size_msat: 0,
		max_payment_size_msat: LSPS2_MAX_PAYMENT_MSAT,
	}
}

/// The new provider, started, as `ldk03-port`'s `core/provider/main.rs` builds it (chain source
/// and logging aside), with its webhook sender recording what it would POST and its wake handler
/// calling `notify_payment_incoming`, as the provider's do.
fn build_new_provider(
	esplora_url: &str, address: &SocketAddress,
) -> (Arc<Node>, mpsc::Receiver<WebhookPost>) {
	let mut config = Config {
		network: bitcoin::Network::Regtest,
		trust_own_splice_inputs_0conf: true,
		hold_private_forwards: true,
		storage_dir_path: storage("new provider"),
		..Default::default()
	};
	config.anchor_channels_config.per_channel_reserve_sats = ANCHOR_RESERVE_PER_CHANNEL_SAT;
	let mut builder = Builder::from_config(config);
	builder.set_inbound_channel_minimum_depth(1);
	builder.set_one_channel_per_peer(true);
	builder.set_node_alias("blocknil-provider".to_string()).unwrap();
	builder.set_forwarding_fees(0, 0);
	builder
		.set_chain_source_esplora(esplora_url.to_owned(), Some(esplora_without_background_sync()));
	builder.set_listening_addresses(vec![address.clone()]).unwrap();
	builder.enable_liquidity_provider(lsps2_terms());
	builder.set_async_payments_role(Some(AsyncPaymentsRole::Server)).unwrap();
	builder.set_liquidity_provider_lsps5(LSPS5ServiceConfig::default());
	let mnemonic = ldk_node::bip39::Mnemonic::from_entropy(&[0x33; 32]).unwrap();
	let node = Arc::new(builder.build(NodeEntropy::from_seed_bytes(mnemonic.to_seed(""))).unwrap());
	node.start().unwrap();

	let (tx, rx) = mpsc::channel();
	let tx = Mutex::new(tx);
	node.set_webhook_sender(Arc::new(move |post| {
		println!("provider POSTs to {}: {}", post.url, post.body);
		let _ = tx.lock().unwrap().send(post);
	}));
	let weak = Arc::downgrade(&node);
	node.set_payment_held_handler(Arc::new(move |customer| {
		let node = weak.upgrade();
		std::thread::spawn(move || {
			if let Some(node) = node {
				println!("provider wakes {}: {}", customer, node.notify_payment_incoming(customer));
			}
		});
	}));
	(node, rx)
}

/// The r8 customer, started and connected to its provider, as r8's `core/src/lightning.rs`
/// builds it (chain source, logging and the BIP 353 resolver aside).
fn build_r8_customer(
	esplora_url: &str, provider: PublicKey, provider_address: &SocketAddress,
) -> r8::Node {
	let mut builder = r8::Builder::new();
	builder.set_network(bitcoin::Network::Regtest);
	builder.set_storage_dir_path(storage("r8 customer"));
	builder.set_chain_source_esplora(
		esplora_url.to_owned(),
		Some(r8::config::EsploraSyncConfig { background_sync_config: None }),
	);
	builder.set_route_messages_via_lsp(true);
	builder.set_gossip_source_p2p();
	builder.set_entropy_seed_bytes([0x22; 64]);
	builder.set_liquidity_source_lsps2(provider, to_r8_address(provider_address), None);
	builder.set_liquidity_client_lsps5();
	builder.add_trusted_peer_no_reserve(provider);
	builder.set_async_payments_role(Some(r8::config::AsyncPaymentsRole::Client)).unwrap();
	let node = builder.build().unwrap();
	node.start().unwrap();
	node.connect(provider, to_r8_address(provider_address), true).unwrap();
	node.set_fee_provider(Some(provider));
	node
}

/// The r8 provider, started, as r8's `core/provider/main.rs` builds it (chain source, logging and
/// the DNS resolver aside).
fn build_r8_provider(esplora_url: &str, address: &SocketAddress) -> r8::Node {
	let mut builder = r8::Builder::new();
	builder.set_network(bitcoin::Network::Regtest);
	builder.set_inbound_channel_minimum_depth(1);
	builder.set_one_channel_per_peer(true);
	builder.set_trust_own_splice_inputs_0conf(true);
	builder.set_forwarding_cltv_expiry_delta(CLTV_EXPIRY_DELTA);
	builder.set_node_alias("blocknil-provider".to_string()).unwrap();
	builder.set_forwarding_fees(0, 0);
	builder.set_anchor_reserve_per_channel_sats(ANCHOR_RESERVE_PER_CHANNEL_SAT);
	builder.set_storage_dir_path(storage("r8 provider"));
	builder.set_chain_source_esplora(
		esplora_url.to_owned(),
		Some(r8::config::EsploraSyncConfig { background_sync_config: None }),
	);
	builder
		.set_entropy_bip39_mnemonic(r8::bip39::Mnemonic::from_entropy(&[0x44; 32]).unwrap(), None);
	builder.set_listening_addresses(vec![to_r8_address(address)]).unwrap();
	builder.set_liquidity_provider_lsps2(lsps2_terms_r8());
	builder.set_async_payments_role(Some(r8::config::AsyncPaymentsRole::Server)).unwrap();
	builder.set_liquidity_provider_lsps5(r8::liquidity::LSPS5ServiceConfig {
		allowed_hosts: vec![PUSH_HOST.to_string()],
		..Default::default()
	});
	let node = builder.build().unwrap();
	node.start().unwrap();
	node
}

/// The new customer, started and connected to its provider, as `ldk03-port`'s
/// `core/src/lightning.rs` builds it (chain source and logging aside).
fn build_new_customer(
	esplora_url: &str, provider: PublicKey, provider_address: &SocketAddress,
) -> Node {
	let mut config = Config {
		network: bitcoin::Network::Regtest,
		storage_dir_path: storage("new customer"),
		route_messages_via_lsp: true,
		..Default::default()
	};
	config.anchor_channels_config.trusted_peers_no_reserve = vec![provider];
	config.hrn_config.resolution_config =
		HRNResolverConfig::Blip32Via { resolver_nodes: vec![provider] };
	let mut builder = Builder::from_config(config);
	builder
		.set_chain_source_esplora(esplora_url.to_owned(), Some(esplora_without_background_sync()));
	builder.set_gossip_source_p2p();
	builder.add_liquidity_source(provider, provider_address.clone(), None, true);
	builder.set_liquidity_client_lsps5();
	builder.set_async_payments_role(Some(AsyncPaymentsRole::Client)).unwrap();
	let node = builder.build(NodeEntropy::from_seed_bytes([0x55; 64])).unwrap();
	node.start().unwrap();
	node.connect(provider, provider_address.clone(), true).unwrap();
	node.set_fee_provider(Some(provider));
	node
}

/// The rest of the network: a plain node of this crate, started.
fn build_payer(esplora_url: &str) -> Node {
	let config = Config {
		network: bitcoin::Network::Regtest,
		storage_dir_path: storage("payer"),
		listening_addresses: Some(generate_listening_addresses()),
		..Default::default()
	};
	let mut builder = Builder::from_config(config);
	builder
		.set_chain_source_esplora(esplora_url.to_owned(), Some(esplora_without_background_sync()));
	let node = builder.build(NodeEntropy::from_seed_bytes([0x11; 64])).unwrap();
	node.start().unwrap();
	node
}

/// The provider's forwarding policy on every channel: no fee, its CLTV delta
/// (`wallet_core::forwarding::apply`), every other field kept.
fn apply_forwarding_policy(provider: &Node) {
	for channel in provider.list_channels() {
		let mut config = channel.config;
		config.forwarding_fee_base_msat = 0;
		config.forwarding_fee_proportional_millionths = 0;
		config.cltv_expiry_delta = CLTV_EXPIRY_DELTA;
		provider
			.update_channel_config(&channel.user_channel_id, channel.counterparty.node_id, config)
			.unwrap();
	}
}

/// An r8 invoice, for this crate's payer: the two crates' invoice types are distinct.
fn from_r8(
	invoice: &r8::lightning_invoice::Bolt11Invoice,
) -> ldk_node::lightning_invoice::Bolt11Invoice {
	invoice.to_string().parse().unwrap()
}

/// One of this crate's invoices, for an r8 node to pay.
fn to_r8(
	invoice: &ldk_node::lightning_invoice::Bolt11Invoice,
) -> r8::lightning_invoice::Bolt11Invoice {
	invoice.to_string().parse().unwrap()
}

fn to_r8_address(address: &SocketAddress) -> r8::lightning::ln::msgs::SocketAddress {
	r8::lightning::ln::msgs::SocketAddress::from_str(&address.to_string()).unwrap()
}

// ---- The provider's reports. ----

fn short_of_room_reports(provider: &Node) -> mpsc::Receiver<ShortOfRoom> {
	let (tx, rx) = mpsc::channel();
	let tx = Mutex::new(tx);
	provider.set_short_of_room_handler(Arc::new(move |short| {
		let _ = tx.lock().unwrap().send(short);
	}));
	rx
}

async fn block_recv<T>(rx: &mpsc::Receiver<T>, wait: Duration) -> Option<T> {
	tokio::task::block_in_place(|| rx.recv_timeout(wait).ok())
}

/// The next webhook POST whose body is the notification `method`, skipping others.
async fn next_post(rx: &mpsc::Receiver<WebhookPost>, method: &str) -> WebhookPost {
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		let left = deadline.saturating_duration_since(Instant::now());
		let post = block_recv(rx, left)
			.await
			.unwrap_or_else(|| panic!("no {} notification was posted", method));
		let body: serde_json::Value = serde_json::from_str(&post.body).unwrap();
		if body["method"] == method {
			return post;
		}
		println!("skipping webhook POST {} while waiting for {}", post.body, method);
	}
}

async fn wait_until_disconnected(provider: &Node, customer: PublicKey) {
	for _ in 0..100 {
		if provider.list_peers().iter().all(|p| p.node_id != customer || !p.is_connected) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	panic!("the customer is still connected");
}

/// An invoice the new wallet makes once it has a channel: through its provider, uncapped. The
/// provider's first channel update may not be in yet, so it is retried for a while.
async fn receive_via_provider(
	customer: &Node, provider: PublicKey, amount_msat: u64,
) -> ldk_node::lightning_invoice::Bolt11Invoice {
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		match customer.bolt11_payment().receive_via_provider(
			Some(amount_msat),
			&description("via provider"),
			3600,
			provider,
		) {
			Ok(invoice) => return invoice,
			Err(e) => {
				assert!(Instant::now() < deadline, "no invoice through the provider: {:?}", e);
				tokio::time::sleep(Duration::from_millis(200)).await;
			},
		}
	}
}

// ---- Waiting on this crate's nodes. ----

const EVENT_TIMEOUT: Duration = Duration::from_secs(90);

/// Waits for the first event matching `want`, handling (and printing) the others.
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
	let deadline = Instant::now() + EVENT_TIMEOUT;
	while !node.list_channels().iter().any(|c| c.counterparty.node_id == peer && c.is_usable) {
		assert!(Instant::now() < deadline, "{}'s channel with {} not usable", node.node_id(), peer);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn claimable_on_close(node: &Node, channel_id: [u8; 32]) -> u64 {
	let amounts: Vec<u64> = node
		.list_balances()
		.lightning_balances
		.iter()
		.filter_map(|b| match b {
			LightningBalance::ClaimableOnChannelClose {
				channel_id: id, amount_satoshis, ..
			} if id.0 == channel_id => Some(*amount_satoshis),
			_ => None,
		})
		.collect();
	assert_eq!(amounts.len(), 1);
	amounts[0]
}

fn description(text: &str) -> ldk_node::lightning_invoice::Bolt11InvoiceDescription {
	ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
		ldk_node::lightning_invoice::Description::new(text.to_string()).unwrap(),
	)
}

// ---- Waiting on the r8 nodes. ----

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

async fn r8_wait_received(node: &r8::Node) -> u64 {
	match r8_wait(node, "a payment", |e| matches!(e, r8::Event::PaymentReceived { .. })).await {
		r8::Event::PaymentReceived { amount_msat, .. } => amount_msat,
		_ => unreachable!(),
	}
}

async fn r8_wait_fee_paid(node: &r8::Node) -> u64 {
	let success = |e: &r8::Event| matches!(e, r8::Event::PaymentSuccessful { .. });
	match r8_wait(node, "a payment's success", success).await {
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
	let deadline = Instant::now() + EVENT_TIMEOUT;
	while !node.list_channels().iter().any(|c| c.counterparty_node_id == peer && c.is_usable) {
		assert!(Instant::now() < deadline, "r8 channel with {} not usable", peer);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn r8_claimable_on_close(node: &r8::Node, channel_id: [u8; 32]) -> u64 {
	let amounts: Vec<u64> = node
		.list_balances()
		.lightning_balances
		.iter()
		.filter_map(|b| match b {
			r8::LightningBalance::ClaimableOnChannelClose {
				channel_id: id,
				amount_satoshis,
				..
			} if id.0 == channel_id => Some(*amount_satoshis),
			_ => None,
		})
		.collect();
	assert_eq!(amounts.len(), 1);
	amounts[0]
}

fn r8_description(text: &str) -> r8::lightning_invoice::Bolt11InvoiceDescription {
	r8::lightning_invoice::Bolt11InvoiceDescription::Direct(
		r8::lightning_invoice::Description::new(text.to_string()).unwrap(),
	)
}
