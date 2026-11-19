// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: held payments and splice on arrival on rust-lightning 0.3, on regtest. A payer
//! pays a customer through the provider (an LSP) that holds the customer's payments.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use common::{
	generate_blocks_and_wait, open_channel, open_channel_no_wait, premine_and_distribute_funds,
	random_config, setup_bitcoind_and_electrsd, setup_node, TestChainSource, TestConfig, TestNode,
	TestStoreType,
};
use electrsd::corepc_node::Node as BitcoinD;
use electrsd::ElectrsD;
use ldk_node::config::AsyncPaymentsRole;
use ldk_node::io::sqlite_store::{SqliteStore, KV_TABLE_NAME, SQLITE_DB_FILE_NAME};
use ldk_node::{Event, ShortOfRoom, UserChannelId};
use lightning::util::persist::KVStore;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};

/// Waits for the first event matching `want`, handling (and printing) the others.
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

fn is_ready_with(peer: PublicKey) -> impl Fn(&Event) -> bool {
	move |e| {
		matches!(e, Event::ChannelReady { counterparty_node_id, .. }
			if *counterparty_node_id == Some(peer))
	}
}

/// `(inbound, outbound)` splice depths of `node`'s channel `user_channel_id`.
fn splice_depths(node: &TestNode, user_channel_id: &UserChannelId) -> (u32, u32) {
	let channel = node
		.list_channels()
		.into_iter()
		.find(|c| &c.user_channel_id == user_channel_id)
		.expect("the channel is listed");
	(channel.config.inbound_splice_min_depth, channel.config.outbound_splice_min_depth)
}

fn user_channel_id(node: &TestNode, funding_txo: bitcoin::OutPoint) -> UserChannelId {
	node.list_channels()
		.into_iter()
		.find(|c| c.funding_txo == Some(funding_txo))
		.expect("the channel is listed")
		.user_channel_id
}

/// The provider locks its own splices at 0 conf (outbound 0, inbound left at 6); the customer
/// locks splices with its provider, a trusted peer, at 0 conf (both 0). On channels opened
/// before either setting (6 and 6, as an older version stored them) the settings are applied at
/// start; on new ones at open and at accept, whichever side opens. A splice of the provider's
/// own coins into the old channel then locks with no block mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn zero_conf_splice_depths_on_new_and_existing_channels() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	// Both restart: their state is on disk.
	let mut provider_config = random_config();
	provider_config.store_type = TestStoreType::Sqlite;
	let mut customer_config = random_config();
	customer_config.store_type = TestStoreType::Sqlite;
	let provider = setup_node(&chain_source, provider_config.clone());
	let customer = setup_node(&chain_source, customer_config.clone());
	let (provider_id, customer_id) = (provider.node_id(), customer.node_id());

	let addresses = vec![
		provider.onchain_payment().new_address().unwrap(),
		provider.onchain_payment().new_address().unwrap(),
		provider.onchain_payment().new_address().unwrap(),
		customer.onchain_payment().new_address().unwrap(),
	];
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(1_000_000),
	)
	.await;
	provider.sync_wallets().unwrap();
	customer.sync_wallets().unwrap();

	// A channel from before the settings: both sides keep rust-lightning's default depths.
	let old_txo = open_channel(&provider, &customer, 500_000, false, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	provider.sync_wallets().unwrap();
	customer.sync_wallets().unwrap();
	wait_for(&provider, "the old channel", is_ready_with(customer_id)).await;
	wait_for(&customer, "the old channel", is_ready_with(provider_id)).await;
	let old_provider = user_channel_id(&provider, old_txo);
	let old_customer = user_channel_id(&customer, old_txo);
	assert_eq!(splice_depths(&provider, &old_provider), (6, 6));
	assert_eq!(splice_depths(&customer, &old_customer), (6, 6));

	// Restart both with the settings: the old channel gets them at start.
	provider.stop().unwrap();
	customer.stop().unwrap();
	drop(provider);
	drop(customer);
	provider_config.node_config.trust_own_splice_inputs_0conf = true;
	customer_config.node_config.trusted_peers_0conf.push(provider_id);
	let provider = setup_node(&chain_source, provider_config);
	let customer = setup_node(&chain_source, customer_config);
	assert_eq!(splice_depths(&provider, &old_provider), (6, 0));
	assert_eq!(splice_depths(&customer, &old_customer), (0, 0));

	// New channels, opened by either side, get them at open and at accept.
	customer
		.connect(provider_id, provider.listening_addresses().unwrap()[0].clone(), true)
		.unwrap();
	let to_provider = open_channel_no_wait(&customer, &provider, 200_000, None, false).await;
	let to_customer = open_channel_no_wait(&provider, &customer, 200_000, None, false).await;
	common::wait_for_tx(&electrsd.client, to_provider.txid).await;
	common::wait_for_tx(&electrsd.client, to_customer.txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	provider.sync_wallets().unwrap();
	customer.sync_wallets().unwrap();
	for _ in 0..2 {
		wait_for(&provider, "a new channel", is_ready_with(customer_id)).await;
		wait_for(&customer, "a new channel", is_ready_with(provider_id)).await;
	}
	for txo in [to_provider, to_customer] {
		assert_eq!(splice_depths(&provider, &user_channel_id(&provider, txo)), (6, 0));
		assert_eq!(splice_depths(&customer, &user_channel_id(&customer, txo)), (0, 0));
	}

	// The provider splices its own coins into the old channel: it locks with no block mined.
	let height = bitcoind.client.get_block_count().unwrap().0;
	provider.splice_in(&old_provider, customer_id, 100_000, None).unwrap();
	let is_old_ready = |old: UserChannelId| move |e: &Event| matches!(e, Event::ChannelReady { user_channel_id, .. } if *user_channel_id == old);
	wait_for(&provider, "the splice to lock", is_old_ready(old_provider)).await;
	wait_for(&customer, "the splice to lock", is_old_ready(old_customer)).await;
	assert_eq!(bitcoind.client.get_block_count().unwrap().0, height, "no block was mined");

	provider.stop().unwrap();
	customer.stop().unwrap();
}

/// A payer with channels of `payer_channels_sats` to the provider; the provider with a channel of
/// `customer_channel_sats` to the customer. The provider holds its clients' payments and locks
/// its own splices at once; the customer trusts it with zero-conf splices. The provider is on
/// disk, so it can restart.
struct Setup {
	bitcoind: BitcoinD,
	electrsd: ElectrsD,
	payer: TestNode,
	provider: TestNode,
	provider_config: TestConfig,
	customer: TestNode,
}

async fn setup(payer_channels_sats: &[u64], customer_channel_sats: u64) -> Setup {
	setup_with(payer_channels_sats, customer_channel_sats, |_, _| {}).await
}

/// [`setup`], with the provider's and the customer's configs adjusted by `adjust` first.
async fn setup_with(
	payer_channels_sats: &[u64], customer_channel_sats: u64,
	adjust: impl FnOnce(&mut TestConfig, &mut TestConfig),
) -> Setup {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	let payer = setup_node(&chain_source, random_config());
	let mut provider_config = random_config();
	provider_config.store_type = TestStoreType::Sqlite;
	provider_config.node_config.hold_private_forwards = true;
	provider_config.node_config.trust_own_splice_inputs_0conf = true;
	let mut customer_config = random_config();
	adjust(&mut provider_config, &mut customer_config);
	let provider = setup_node(&chain_source, provider_config.clone());
	customer_config.node_config.trusted_peers_0conf.push(provider.node_id());
	let customer = setup_node(&chain_source, customer_config);

	let mut addresses = vec![];
	for _ in payer_channels_sats {
		addresses.push(payer.onchain_payment().new_address().unwrap());
	}
	for _ in 0..3 {
		addresses.push(provider.onchain_payment().new_address().unwrap());
	}
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(2_000_000),
	)
	.await;
	payer.sync_wallets().unwrap();
	provider.sync_wallets().unwrap();

	let mut txids = vec![];
	for sats in payer_channels_sats {
		txids.push(open_channel_no_wait(&payer, &provider, *sats, None, false).await.txid);
	}
	txids.push(
		open_channel_no_wait(&provider, &customer, customer_channel_sats, None, false).await.txid,
	);
	for txid in txids {
		common::wait_for_tx(&electrsd.client, txid).await;
	}
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	// In whatever order: the customer's channel is zero-conf (it trusts the provider).
	for _ in payer_channels_sats {
		wait_for(&payer, "a payer channel", is_ready_with(provider.node_id())).await;
	}
	for _ in 0..=payer_channels_sats.len() {
		wait_for(&provider, "a channel", |e| matches!(e, Event::ChannelReady { .. })).await;
	}
	wait_for(&customer, "the customer channel", is_ready_with(provider.node_id())).await;
	for sats in payer_channels_sats {
		common::wait_for_channel_ready_to_send(&payer, &provider, sats * 900).await;
	}

	Setup { bitcoind, electrsd, payer, provider, provider_config, customer }
}

impl Setup {
	fn stop(&self) {
		for node in [&self.payer, &self.provider, &self.customer] {
			let _ = node.stop();
		}
	}

	/// What the provider's channel to the customer can take right now.
	fn room_msat(&self) -> u64 {
		self.provider
			.list_channels()
			.into_iter()
			.filter(|c| c.counterparty.node_id == self.customer.node_id() && c.is_usable)
			.map(|c| c.next_outbound_htlc_limit_msat)
			.max()
			.unwrap_or(0)
	}

	/// Leaves the customer about `room_msat` of room, by paying them the rest (a payment that
	/// fits, forwarded at once although it is intercepted).
	async fn shrink_room_to(&self, room_msat: u64) {
		let amount_msat = self.room_msat() - room_msat;
		self.payer.bolt11_payment().send(&invoice(&self.customer, amount_msat), None).unwrap();
		wait_for(&self.customer, "the payment that fits", is_received(amount_msat)).await;
		wait_for(&self.payer, "its success", is_successful).await;
	}

	fn customer_channel(&self) -> UserChannelId {
		self.provider
			.list_channels()
			.into_iter()
			.find(|c| c.counterparty.node_id == self.customer.node_id())
			.unwrap()
			.user_channel_id
	}

	fn height(&self) -> u64 {
		self.bitcoind.client.get_block_count().unwrap().0
	}
}

fn invoice(customer: &TestNode, amount_msat: u64) -> Bolt11Invoice {
	let description =
		Bolt11InvoiceDescription::Direct(Description::new("held".to_string()).unwrap());
	customer.bolt11_payment().receive(amount_msat, &description, 3600).unwrap()
}

fn is_received(amount_msat: u64) -> impl Fn(&Event) -> bool {
	move |e| matches!(e, Event::PaymentReceived { amount_msat: a, .. } if *a == amount_msat)
}

fn is_successful(e: &Event) -> bool {
	matches!(e, Event::PaymentSuccessful { .. })
}

fn is_failed(e: &Event) -> bool {
	matches!(e, Event::PaymentFailed { .. })
}

/// Collects the provider's short-of-room reports.
fn short_of_room_reports(provider: &TestNode) -> mpsc::Receiver<ShortOfRoom> {
	let (tx, rx) = mpsc::channel();
	let tx = Mutex::new(tx);
	provider.set_short_of_room_handler(Arc::new(move |short| {
		let _ = tx.lock().unwrap().send(short);
	}));
	rx
}

async fn next_report(rx: &mpsc::Receiver<ShortOfRoom>, wait: Duration) -> Option<ShortOfRoom> {
	tokio::task::block_in_place(|| rx.recv_timeout(wait).ok())
}

/// A payment that fits goes straight through; one too large for the customer's room is held
/// and reported once; the provider splices its own coins in and lets it go; the customer gets it
/// with no block mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_of_room_is_spliced_and_forwarded_without_a_block() {
	let s = setup(&[1_000_000], 300_000).await;
	let reports = short_of_room_reports(&s.provider);
	let large = invoice(&s.customer, 150_000_000);

	s.shrink_room_to(50_000_000).await;
	assert!(next_report(&reports, Duration::from_secs(1)).await.is_none(), "it fit");
	assert!(s.provider.held_payments().is_empty());
	assert!(s.provider.recent_held_payments().is_empty(), "a payment that fits isn't a hold");

	let height = s.height();
	s.payer.bolt11_payment().send(&large, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reported");
	assert_eq!(short.customer, s.customer.node_id());
	assert_eq!(short.amount_msat, 150_000_000);
	assert_eq!(short.payment_hash.0, large.payment_hash().0);
	assert!(short.room_msat < short.amount_msat);
	assert_eq!(s.provider.held_payments().len(), 1);
	assert!(next_report(&reports, Duration::from_secs(1)).await.is_none(), "reported once");

	s.provider.splice_in(&s.customer_channel(), s.customer.node_id(), 300_000, None).unwrap();
	s.provider.set_held_payment_fee(short.intercept_id, 0).unwrap();
	// The payment goes out as the splice locks (re-signalled as `ChannelReady`), not on the
	// provider's 5 s fallback timer.
	wait_for(&s.provider, "the splice to lock", is_ready_with(s.customer.node_id())).await;
	let locked = Instant::now();
	while s.provider.recent_held_payments().is_empty() {
		assert!(locked.elapsed() < Duration::from_secs(10), "never forwarded");
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	println!("forwarded {:?} after the splice locked", locked.elapsed());
	assert!(locked.elapsed() < Duration::from_millis(500), "released as the splice locked");
	wait_for(&s.customer, "the large payment", is_received(150_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	assert!(s.provider.held_payments().is_empty());
	assert_eq!(s.height(), height, "the splice locked with no block mined");
	let record = &s.provider.recent_held_payments()[0];
	assert!(record.forwarded);
	assert_eq!(record.amount_msat, 150_000_000);
	s.stop();
}

/// A refused payment fails back to the payer at once, not at the hold's deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_payment_fails_back_at_once() {
	let s = setup(&[1_000_000], 300_000).await;
	let reports = short_of_room_reports(&s.provider);
	let large = invoice(&s.customer, 150_000_000);
	s.shrink_room_to(50_000_000).await;

	s.payer.bolt11_payment().send(&large, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reported");
	let started = Instant::now();
	s.provider.refuse_held_payment(short.intercept_id, "no coins").unwrap();
	wait_for(&s.payer, "the refusal", is_failed).await;
	assert!(started.elapsed() < Duration::from_secs(10), "failed at once");
	assert!(s.provider.held_payments().is_empty());
	assert!(s.provider.refuse_held_payment(short.intercept_id, "again").is_err());
	let record = &s.provider.recent_held_payments()[0];
	assert!(!record.forwarded);
	assert_eq!(record.refused.as_deref(), Some("no coins"));
	s.stop();
}

/// A multi-part payment too large for the room: each part is reported, with the payment's hash;
/// once room is added, every part goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_part_payment_short_of_room_is_reported_per_part() {
	// Payer channels too small for the payment alone: the payer splits it.
	let s = setup(&[120_000, 120_000, 120_000, 120_000], 250_000).await;
	let reports = short_of_room_reports(&s.provider);
	let large = invoice(&s.customer, 200_000_000);
	s.shrink_room_to(40_000_000).await;

	s.payer.bolt11_payment().send(&large, None).unwrap();
	let mut parts = vec![];
	while parts.iter().map(|p: &ShortOfRoom| p.amount_msat).sum::<u64>() < 200_000_000 {
		parts.push(next_report(&reports, Duration::from_secs(30)).await.expect("a part reported"));
	}
	println!("{} parts reported: {:?}", parts.len(), parts);
	assert!(parts.len() >= 2, "a multi-part payment");
	for part in &parts {
		assert_eq!(part.payment_hash.0, large.payment_hash().0);
		assert!(part.room_msat < part.amount_msat);
	}
	assert_eq!(parts.iter().map(|p| p.amount_msat).sum::<u64>(), 200_000_000);
	assert_eq!(s.provider.held_payments().len(), parts.len());

	s.provider.splice_in(&s.customer_channel(), s.customer.node_id(), 300_000, None).unwrap();
	for part in &parts {
		s.provider.set_held_payment_fee(part.intercept_id, 0).unwrap();
	}
	wait_for(&s.customer, "the multi-part payment", is_received(200_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	assert!(s.provider.held_payments().is_empty());
	s.stop();
}

/// Waits until the provider sees the customer gone.
async fn wait_until_disconnected(provider: &TestNode, customer: PublicKey) {
	for _ in 0..100 {
		if provider.list_peers().iter().all(|p| p.node_id != customer || !p.is_connected) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	panic!("the customer is still connected");
}

/// Collects the customers the provider asks to wake.
fn wake_requests(provider: &TestNode) -> mpsc::Receiver<PublicKey> {
	let (tx, rx) = mpsc::channel();
	let tx = Mutex::new(tx);
	provider.set_payment_held_handler(Arc::new(move |customer| {
		let _ = tx.lock().unwrap().send(customer);
	}));
	rx
}

/// A payment for an offline customer is held and the customer woken; it goes out the moment they
/// reconnect, well before the fallback timer would have caught it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_customer_payment_goes_out_on_reconnect() {
	let s = setup(&[1_000_000], 500_000).await;
	let woken = wake_requests(&s.provider);
	let payment = invoice(&s.customer, 50_000_000);
	let customer_id = s.customer.node_id();
	s.customer.stop().unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;

	s.payer.bolt11_payment().send(&payment, None).unwrap();
	let who = tokio::task::block_in_place(|| woken.recv_timeout(Duration::from_secs(30)))
		.expect("the provider holds the payment and asks to wake the customer");
	assert_eq!(who, customer_id);
	assert_eq!(s.provider.held_payments().len(), 1);

	// The customer comes back, and dials its provider as a phone does. The provider forwards
	// the payment once the channel is reestablished: well before its 5 s fallback timer.
	tokio::time::sleep(Duration::from_secs(2)).await;
	s.customer.start().unwrap();
	s.customer
		.connect(s.provider.node_id(), s.provider.listening_addresses().unwrap()[0].clone(), true)
		.unwrap();
	let connected = Instant::now();
	while s.provider.recent_held_payments().is_empty() {
		assert!(connected.elapsed() < Duration::from_secs(10), "never forwarded");
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let took = connected.elapsed();
	println!("the provider forwarded the held payment {:?} after the customer connected", took);
	assert!(
		took < Duration::from_millis(1500),
		"released on reconnect, not by the timer: {took:?}"
	);
	assert!(s.provider.recent_held_payments()[0].forwarded);
	wait_for(&s.customer, "the held payment", is_received(50_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	assert!(s.provider.held_payments().is_empty());
	s.stop();
}

/// The provider restarts while it holds a payment for an offline customer: LDK hands the
/// intercepted HTLC back after the restart, it is held again, and goes out when the customer is
/// back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_payment_survives_a_provider_restart() {
	let s = setup(&[1_000_000], 500_000).await;
	let woken = wake_requests(&s.provider);
	let payment = invoice(&s.customer, 50_000_000);
	let customer_id = s.customer.node_id();
	s.customer.stop().unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;
	s.payer.bolt11_payment().send(&payment, None).unwrap();
	tokio::task::block_in_place(|| woken.recv_timeout(Duration::from_secs(30))).expect("held");

	// Restart the provider with the payment held.
	s.provider.stop().unwrap();
	let chain_source = TestChainSource::Esplora(&s.electrsd);
	let provider = setup_node(&chain_source, s.provider_config.clone());
	// The provider may be dialling the payer at the same time: a failed connect is no matter.
	let _ = s.payer.connect(
		provider.node_id(),
		provider.listening_addresses().unwrap()[0].clone(),
		true,
	);
	// The HTLC comes back as the node starts, before the application sets its wake handler (an
	// LSPS2 provider may even handle it inside `start`): it is held, and the handler set later
	// is still told.
	let back = Instant::now();
	while provider.held_payments().is_empty() {
		assert!(back.elapsed() < Duration::from_secs(30), "never held again");
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let woken = wake_requests(&provider);
	let who = tokio::task::block_in_place(|| woken.recv_timeout(Duration::from_secs(10)))
		.expect("the wake handler set after the restart is told");
	assert_eq!(who, customer_id);
	assert_eq!(provider.held_payments().len(), 1);

	s.customer.start().unwrap();
	let _ = s.customer.connect(
		provider.node_id(),
		provider.listening_addresses().unwrap()[0].clone(),
		true,
	);
	wait_for(&s.customer, "the held payment", is_received(50_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	assert!(provider.held_payments().is_empty());
	provider.stop().unwrap();
	s.stop();
}

impl Setup {
	/// Stops the provider, sets its stored hold SCIDs to `hold_scids` (as r8 or an earlier run
	/// left them), and starts it again; payer and customer reconnect.
	async fn restart_provider_with_hold_scids(&mut self, hold_scids: String) {
		self.provider.stop().unwrap();
		let store = SqliteStore::new(
			self.provider_config.node_config.storage_dir_path.clone().into(),
			Some(SQLITE_DB_FILE_NAME.to_string()),
			Some(KV_TABLE_NAME.to_string()),
		)
		.unwrap();
		KVStore::write(&store, "blocknil", "", "hold_scids", hold_scids.into_bytes())
			.await
			.unwrap();
		drop(store);
		let chain_source = TestChainSource::Esplora(&self.electrsd);
		self.provider = setup_node(&chain_source, self.provider_config.clone());
		let address = self.provider.listening_addresses().unwrap()[0].clone();
		// The provider may be dialling them at the same time: a failed connect is no matter.
		let _ = self.payer.connect(self.provider.node_id(), address.clone(), true);
		let _ = self.customer.connect(self.provider.node_id(), address, true);
		common::wait_for_channel_ready_to_send(&self.payer, &self.provider, 100_000_000).await;
		common::wait_for_channel_ready_to_send(&self.provider, &self.customer, 100_000_000).await;
	}

	fn stored_hold_scids(&self) -> String {
		let store = SqliteStore::new(
			self.provider_config.node_config.storage_dir_path.clone().into(),
			Some(SQLITE_DB_FILE_NAME.to_string()),
			Some(KV_TABLE_NAME.to_string()),
		)
		.unwrap();
		let bytes = tokio::task::block_in_place(|| {
			tokio::runtime::Handle::current().block_on(KVStore::read(
				&store,
				"blocknil",
				"",
				"hold_scids",
			))
		});
		String::from_utf8(bytes.unwrap()).unwrap()
	}
}

/// Invoices phones handed out before the upgrade carry the provider's hold SCID for them. After
/// the upgrade the provider reads r8's stored hold SCIDs, and a payment on one reaches its
/// customer; 30 days after the new code first saw it, the SCID is no longer honoured: a payment
/// on it fails at once, and the customer gets no new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_hold_scid_invoices_keep_working_for_30_days() {
	let mut s = setup(&[1_000_000], 500_000).await;
	let (provider_id, customer_id) = (s.provider.node_id(), s.customer.node_id());
	let scid = s.provider.hold_scid_for(customer_id).unwrap();
	assert_eq!(s.provider.hold_scid_for(customer_id).unwrap(), scid, "one per customer");
	let cltv_expiry_delta = s.provider.list_channels()[0].config.cltv_expiry_delta;
	let description =
		Bolt11InvoiceDescription::Direct(Description::new("old".to_string()).unwrap());
	let old_invoice = |amount_msat| {
		s.customer
			.bolt11_payment()
			.receive_via_hold_scid(
				Some(amount_msat),
				&description,
				3600,
				provider_id,
				scid,
				cltv_expiry_delta,
			)
			.unwrap()
	};
	let (first, second) = (old_invoice(20_000_000), old_invoice(30_000_000));
	assert_eq!(first.route_hints()[0].0[0].short_channel_id, scid);

	// The upgrade: the provider starts on this code with the hold SCIDs as r8 stored them.
	let r8_line = format!("{scid:016x} {customer_id}\n");
	s.restart_provider_with_hold_scids(r8_line).await;
	s.payer.bolt11_payment().send(&first, None).unwrap();
	wait_for(&s.customer, "the old invoice's payment", is_received(20_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	// The 30 days run from the upgrade: saved with the SCID.
	let stored = s.stored_hold_scids();
	let first_seen: u64 = stored.trim().rsplit(' ').next().unwrap().parse().unwrap();
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	assert!(now - first_seen < 600, "first seen at the upgrade: {stored}");

	// 31 days later the SCID is no longer honoured.
	let lapsed = now - 31 * 24 * 3600;
	s.restart_provider_with_hold_scids(format!("{scid:016x} {customer_id} {lapsed}\n")).await;
	let started = Instant::now();
	s.payer.bolt11_payment().send(&second, None).unwrap();
	wait_for(&s.payer, "the lapsed invoice's failure", is_failed).await;
	assert!(started.elapsed() < Duration::from_secs(10), "failed at once");
	assert!(s.provider.hold_scid_for(customer_id).is_err(), "no new hold SCID once it lapsed");
	s.stop();
}

/// A customer's ordinary invoice caps the provider's hint at the room it has today, so a payer
/// can't even try a payment larger than that. The provider invoice carries no cap: the payment
/// reaches the provider, which splices room in, and the customer gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_invoice_lets_a_payment_larger_than_the_room_arrive() {
	let s = setup(&[1_500_000], 300_000).await;
	let reports = short_of_room_reports(&s.provider);
	assert!(s.room_msat() < 400_000_000);

	let capped = invoice(&s.customer, 400_000_000);
	let sent = s.payer.bolt11_payment().send(&capped, None);
	if sent.is_ok() {
		wait_for(&s.payer, "the capped invoice's failure", is_failed).await;
	}
	assert!(next_report(&reports, Duration::from_secs(1)).await.is_none(), "never reached it");

	let description =
		Bolt11InvoiceDescription::Direct(Description::new("room".to_string()).unwrap());
	let uncapped = s
		.customer
		.bolt11_payment()
		.receive_via_provider(Some(400_000_000), &description, 3600, s.provider.node_id())
		.unwrap();
	let hint = &uncapped.route_hints()[0].0[0];
	assert_eq!(hint.src_node_id, s.provider.node_id());
	assert_eq!(hint.htlc_maximum_msat, None);
	s.payer.bolt11_payment().send(&uncapped, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reached the provider");
	assert_eq!(short.amount_msat, 400_000_000);
	s.provider.splice_in(&s.customer_channel(), s.customer.node_id(), 300_000, None).unwrap();
	s.provider.set_held_payment_fee(short.intercept_id, 0).unwrap();
	wait_for(&s.customer, "the large payment", is_received(400_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	s.stop();
}

/// The provider holds a payment of `amount_msat` to the customer, short of room, splices room in
/// and keeps `fee_msat` out of it; the customer has allowed `allowance_msat` for it. Returns
/// whether the customer claimed it (and checks what it got).
async fn splice_on_arrival_with_fee(
	s: &Setup, amount_msat: u64, allowance_msat: Option<u64>, fee_msat: u64,
) -> bool {
	let reports = short_of_room_reports(&s.provider);
	let description =
		Bolt11InvoiceDescription::Direct(Description::new("fee".to_string()).unwrap());
	let invoice = s
		.customer
		.bolt11_payment()
		.receive_via_provider(Some(amount_msat), &description, 3600, s.provider.node_id())
		.unwrap();
	let payment_hash = lightning_types::payment::PaymentHash(invoice.payment_hash().0);
	if let Some(allowance_msat) = allowance_msat {
		s.customer.allow_provider_fee(payment_hash, allowance_msat).unwrap();
	}
	s.payer.bolt11_payment().send(&invoice, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reported");
	s.provider.splice_in(&s.customer_channel(), s.customer.node_id(), 300_000, None).unwrap();
	s.provider.set_held_payment_fee(short.intercept_id, fee_msat).unwrap();
	let outcome =
		wait_for(&s.payer, "the payment's outcome", |e| is_successful(e) || is_failed(e)).await;
	if is_successful(&outcome) {
		wait_for(&s.customer, "the payment less the fee", is_received(amount_msat - fee_msat))
			.await;
		true
	} else {
		false
	}
}

/// The customer allowed its provider a fee for this payment: the provider keeps it, and the
/// customer claims the rest. The allowance is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_fee_within_the_allowance_is_claimed() {
	let s = setup(&[1_500_000], 300_000).await;
	s.customer.set_fee_provider(Some(s.provider.node_id()));
	assert!(splice_on_arrival_with_fee(&s, 400_000_000, Some(1_000_000), 1_000_000).await);
	assert!(s.customer.provider_fee_allowances().is_empty(), "spent");
	assert_eq!(s.provider.recent_held_payments()[0].fee_msat, 1_000_000);
	s.stop();
}

/// A fee larger than the allowance is refused, and so is one kept by a peer that isn't our fee
/// provider, even for a payment we gave an allowance for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_fee_above_the_allowance_or_from_another_peer_is_refused() {
	let s = setup(&[1_500_000], 300_000).await;
	s.customer.set_fee_provider(Some(s.provider.node_id()));
	assert!(!splice_on_arrival_with_fee(&s, 400_000_000, Some(500_000), 1_000_000).await);

	// Our fee provider is someone else now; the provider's channel still takes underpaying
	// HTLCs, so it is our check that refuses the fee.
	s.customer.set_fee_provider(Some(s.payer.node_id()));
	let channel = s.customer.list_channels().into_iter().next().unwrap();
	assert!(channel.config.accept_underpaying_htlcs);
	assert!(!splice_on_arrival_with_fee(&s, 700_000_000, Some(1_000_000), 1_000_000).await);
	s.stop();
}

/// rust-lightning doesn't persist a channel's `accept_underpaying_htlcs`. A client sets it again
/// at start on its channels with its LSP, and on a channel with its fee provider as soon as it is
/// ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_underpaying_is_set_again_at_start_and_on_channel_ready() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);
	let provider = setup_node(&chain_source, random_config());
	let provider_address = provider.listening_addresses().unwrap()[0].clone();
	let customer_config = random_config();
	let customer_store =
		common::TestSyncStore::new(customer_config.node_config.storage_dir_path.clone().into());
	// The customer, with the provider as its LSP.
	let customer_with_lsp = || {
		let mut builder = ldk_node::Builder::from_config(customer_config.node_config.clone());
		common::configure_chain_source(&chain_source, &mut builder, &customer_config);
		builder.set_filesystem_logger(None, None);
		builder.add_liquidity_source(provider.node_id(), provider_address.clone(), None, true);
		let node =
			builder.build_with_store(customer_config.node_entropy, customer_store.clone()).unwrap();
		node.start().unwrap();
		node
	};
	let customer = customer_with_lsp();
	let addresses = (0..2).map(|_| provider.onchain_payment().new_address().unwrap()).collect();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(1_000_000),
	)
	.await;
	provider.sync_wallets().unwrap();
	let underpaying = |node: &ldk_node::Node| -> Vec<bool> {
		node.list_channels().iter().map(|c| c.config.accept_underpaying_htlcs).collect()
	};

	open_channel(&provider, &customer, 200_000, false, &electrsd).await;
	wait_for(&customer, "the channel", is_ready_with(provider.node_id())).await;
	wait_for(&provider, "the channel", is_ready_with(customer.node_id())).await;
	assert_eq!(underpaying(&customer), vec![false]);
	customer.set_fee_provider(Some(provider.node_id()));
	assert_eq!(underpaying(&customer), vec![true]);

	// A restart forgets it; the LSP's channels get it back at start.
	customer.stop().unwrap();
	drop(customer);
	let customer = customer_with_lsp();
	assert_eq!(underpaying(&customer), vec![true]);

	// A new channel with the fee provider gets it once ready.
	customer.set_fee_provider(Some(provider.node_id()));
	let _ = customer.connect(provider.node_id(), provider_address.clone(), true);
	open_channel(&provider, &customer, 200_000, false, &electrsd).await;
	wait_for(&customer, "the new channel", is_ready_with(provider.node_id())).await;
	wait_for(&provider, "the new channel", is_ready_with(customer.node_id())).await;
	assert_eq!(underpaying(&customer), vec![true, true]);

	provider.stop().unwrap();
	customer.stop().unwrap();
}

/// LDK builds a BOLT 12 invoice's paths only through channels with the room for the amount, so a
/// customer short of room couldn't even answer an offer payment. With its provider set, its
/// invoice carries a path through the provider: the payment reaches it, is reported short of
/// room, and arrives once room is spliced in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_payment_larger_than_the_room_reaches_the_provider() {
	let s = setup(&[1_500_000], 300_000).await;
	let reports = short_of_room_reports(&s.provider);
	s.customer.set_fee_provider(Some(s.provider.node_id()));
	let offer = s.customer.bolt12_payment().receive_variable_amount("room", None).unwrap();

	s.payer.bolt12_payment().send_using_amount(&offer, 400_000_000, None, None, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reached the provider");
	assert_eq!(short.customer, s.customer.node_id());
	assert_eq!(short.amount_msat, 400_000_000);
	s.provider.splice_in(&s.customer_channel(), s.customer.node_id(), 300_000, None).unwrap();
	s.provider.set_held_payment_fee(short.intercept_id, 0).unwrap();
	wait_for(&s.customer, "the offer payment", is_received(400_000_000)).await;
	wait_for(&s.payer, "its success", is_successful).await;
	s.stop();
}

/// A BOLT 12 invoice request for an offline customer waits in the provider's mailbox (an
/// async-payments server) and is handed over the moment the customer connects. The customer must
/// answer with an invoice that has a path to it, and the payment must arrive. r8 held such
/// messages until the customer's channel was usable, as an invoice built before it is has no path
/// (`MissingPaths`); on rust-lightning 0.3 the provider's `channel_reestablish` reaches the
/// customer before the released messages do, which this test guards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invoice_request_for_an_offline_customer_is_answered_when_it_is_back() {
	let s = setup_with(&[1_000_000], 500_000, |provider, customer| {
		// As the provider and the wallet run: the provider keeps onion messages for offline
		// clients, the wallet is its async-payments client.
		provider.async_payments_role = Some(AsyncPaymentsRole::Server);
		customer.async_payments_role = Some(AsyncPaymentsRole::Client);
	})
	.await;
	s.customer.set_fee_provider(Some(s.provider.node_id()));
	let offer = s.customer.bolt12_payment().receive_variable_amount("offline", None).unwrap();
	let customer_id = s.customer.node_id();
	s.customer.stop().unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;

	s.payer.bolt12_payment().send_using_amount(&offer, 50_000_000, None, None, None).unwrap();
	// The invoice request reaches the provider and waits there for the customer. So does the
	// payer's one retry of it, sent on the first message the payer receives afterwards (a ping
	// within 30 s, in a debug build): from here on, only the provider's mailbox can answer it.
	tokio::time::sleep(Duration::from_secs(35)).await;

	// The customer comes back as a phone does: it starts, then dials its provider.
	s.customer.start().unwrap();
	s.customer
		.connect(s.provider.node_id(), s.provider.listening_addresses().unwrap()[0].clone(), true)
		.unwrap();
	let connected = Instant::now();
	let outcome =
		wait_for(&s.payer, "the payment's outcome", |e| is_successful(e) || is_failed(e)).await;
	assert!(is_successful(&outcome), "the customer answered with a usable invoice: {outcome:?}");
	println!("the payment succeeded {:?} after the customer connected", connected.elapsed());
	wait_for(&s.customer, "the offer payment", is_received(50_000_000)).await;
	s.stop();
}

/// Decision 4 (rl-19 isn't ported): a payment the provider forwards to a customer who drops
/// before rust-lightning adds it to their channel (on its next forwarding pass, ~50 ms later) is
/// failed back, not handed back to be held again. The provider logs and counts each one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_lost_to_a_customer_going_offline_is_counted() {
	let s = setup(&[1_000_000], 300_000).await;
	let reports = short_of_room_reports(&s.provider);
	let customer_id = s.customer.node_id();
	s.shrink_room_to(50_000_000).await;
	assert_eq!(s.provider.forwards_failed_offline(), 0, "a forward that went through");

	// The provider's `disconnect` removes the peer from its store before it disconnects, a write
	// that takes a while. With the customer no longer in it (dialling back doesn't add it), the
	// disconnect below happens at once.
	s.provider.disconnect(customer_id).unwrap();
	wait_until_disconnected(&s.provider, customer_id).await;
	wait_until_disconnected(&s.customer, s.provider.node_id()).await;
	s.customer
		.connect(s.provider.node_id(), s.provider.listening_addresses().unwrap()[0].clone(), true)
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(10);
	while s.room_msat() == 0 {
		assert!(Instant::now() < deadline, "the customer's channel is usable again");
		tokio::time::sleep(Duration::from_millis(10)).await;
	}

	// A payment larger than the room is held. The provider lets it go for less (a fee that leaves
	// 40,000 sats, which fit): it is forwarded inside this call, and the customer is dropped at
	// once, before the forwarding pass.
	let large = invoice(&s.customer, 150_000_000);
	s.payer.bolt11_payment().send(&large, None).unwrap();
	let short = next_report(&reports, Duration::from_secs(30)).await.expect("reported");
	s.provider.set_held_payment_fee(short.intercept_id, 110_000_000).unwrap();
	s.provider.disconnect(customer_id).unwrap();

	let deadline = Instant::now() + Duration::from_secs(10);
	while s.provider.forwards_failed_offline() == 0 {
		assert!(Instant::now() < deadline, "the lost forward was never counted");
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert_eq!(s.provider.forwards_failed_offline(), 1);
	// The admin console's record of it says it was failed back, not delivered, and kept no fee.
	let record = s
		.provider
		.recent_held_payments()
		.into_iter()
		.find(|r| r.payment_hash == large.payment_hash())
		.expect("the lost payment's record");
	assert!(!record.forwarded, "{record:?}");
	assert_eq!(record.fee_msat, 0);
	assert!(
		record.refused.as_deref().is_some_and(|why| why.contains("went offline")),
		"{record:?}"
	);
	s.stop();
}
