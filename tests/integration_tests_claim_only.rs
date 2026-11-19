// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil: a wallet's claim-only start (its notification extension, woken while the app is
//! closed) and the onion messages a wallet routes through its provider.

mod common;

use lightning::io;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use common::{
	expect_channel_ready_event, expect_payment_received_event, expect_payment_successful_event,
	generate_blocks_and_wait, open_channel, open_channel_push_amt, premine_and_distribute_funds,
	random_config, setup_bitcoind_and_electrsd, setup_builder, setup_node, TestChainSource,
	TestConfig, TestNode, TestSyncStore,
};
use ldk_node::config::AsyncPaymentsRole;
use ldk_node::{Builder, Event};
use lightning::routing::gossip::NodeId;
use lightning::util::persist::{
	KVStore, PageToken, PaginatedKVStore, PaginatedListResponse, NETWORK_GRAPH_PERSISTENCE_KEY,
	SCORER_PERSISTENCE_KEY,
};
use lightning_invoice::{Bolt11InvoiceDescription, Description};

/// The key ldk-node caches external pathfinding scores under (not exported by ldk-node).
const EXTERNAL_PATHFINDING_SCORES_CACHE_KEY: &str = "external_pathfinding_scores_cache";

/// What a wallet core wraps its store in for a claim-only start: the network graph, the scorer
/// and the external scores cache read as absent, so the node starts with an empty graph and
/// scorer, and their writes are dropped, so the app's copies stay as they were. Everything else
/// passes through.
#[derive(Clone)]
struct ClaimOnlyStore {
	inner: TestSyncStore,
	dropped_writes: Arc<AtomicUsize>,
}

impl ClaimOnlyStore {
	fn new(inner: TestSyncStore) -> Self {
		Self { inner, dropped_writes: Arc::new(AtomicUsize::new(0)) }
	}

	fn is_off_limits(primary_namespace: &str, secondary_namespace: &str, key: &str) -> bool {
		primary_namespace.is_empty()
			&& secondary_namespace.is_empty()
			&& [
				NETWORK_GRAPH_PERSISTENCE_KEY,
				SCORER_PERSISTENCE_KEY,
				EXTERNAL_PATHFINDING_SCORES_CACHE_KEY,
			]
			.contains(&key)
	}
}

impl KVStore for ClaimOnlyStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, io::Error>> + 'static + Send {
		let inner = (!Self::is_off_limits(primary_namespace, secondary_namespace, key))
			.then(|| self.inner.read(primary_namespace, secondary_namespace, key));
		async move {
			match inner {
				Some(read) => read.await,
				None => {
					Err(io::Error::new(io::ErrorKind::NotFound, "not read on a claim-only start"))
				},
			}
		}
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		let inner = if Self::is_off_limits(primary_namespace, secondary_namespace, key) {
			self.dropped_writes.fetch_add(1, Ordering::Relaxed);
			None
		} else {
			Some(self.inner.write(primary_namespace, secondary_namespace, key, buf))
		};
		async move {
			match inner {
				Some(write) => write.await,
				None => Ok(()),
			}
		}
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		self.inner.remove(primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, io::Error>> + 'static + Send {
		self.inner.list(primary_namespace, secondary_namespace)
	}
}

impl PaginatedKVStore for ClaimOnlyStore {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> impl Future<Output = Result<PaginatedListResponse, io::Error>> + 'static + Send {
		self.inner.list_paginated(primary_namespace, secondary_namespace, page_token)
	}
}

/// This process's thread count and resident memory, where the platform tells (macOS).
fn process_threads_and_resident_bytes() -> Option<(i32, u64)> {
	#[cfg(target_os = "macos")]
	{
		let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
		let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
		let written = unsafe {
			libc::proc_pidinfo(
				libc::getpid(),
				libc::PROC_PIDTASKINFO,
				0,
				&mut info as *mut _ as *mut libc::c_void,
				size,
			)
		};
		(written == size).then_some((info.pti_threadnum, info.pti_resident_size))
	}
	#[cfg(not(target_os = "macos"))]
	None
}

/// A wallet's claim-only start, the way its notification extension does it: built around the
/// wallet core's store wrapper and a 2-worker runtime of its own, pointed at a chain server it
/// cannot reach. It still starts, and claims a payment its provider forwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn claim_only_start_claims_without_the_chain() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	let payer = setup_node(&chain_source, random_config());
	let provider = setup_node(&chain_source, random_config());
	// The wallet: unannounced, like a phone.
	let mut wallet_config = random_config();
	wallet_config.node_config.listening_addresses = None;
	wallet_config.node_config.node_alias = None;
	let wallet_store =
		TestSyncStore::new(wallet_config.node_config.storage_dir_path.clone().into());
	let wallet =
		common::setup_node_with_store(&chain_source, wallet_config.clone(), wallet_store.clone());

	let addresses = vec![
		payer.onchain_payment().new_address().unwrap(),
		wallet.onchain_payment().new_address().unwrap(),
	];
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(2_000_000),
	)
	.await;
	payer.sync_wallets().unwrap();
	wallet.sync_wallets().unwrap();

	// payer -- provider (announced), provider -- wallet (unannounced, half pushed to the provider
	// so the wallet can receive).
	open_channel(&payer, &provider, 1_000_000, true, &electrsd).await;
	open_channel_push_amt(&wallet, &provider, 1_000_000, Some(500_000_000), false, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &wallet] {
		node.sync_wallets().unwrap();
	}
	expect_channel_ready_event!(payer, provider.node_id());
	expect_channel_ready_event!(provider, payer.node_id());
	expect_channel_ready_event!(wallet, provider.node_id());
	expect_channel_ready_event!(provider, wallet.node_id());

	// The app hands out an invoice and closes, with the network graph it learned in its store.
	while wallet.network_graph().list_channels().is_empty() {
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let amount_msat = 50_000_000;
	let description = Bolt11InvoiceDescription::Direct(Description::new("claim".into()).unwrap());
	let invoice = wallet.bolt11_payment().receive(amount_msat, &description, 3600).unwrap();
	let app_status = wallet.status();
	wallet.stop().unwrap();
	drop(wallet);
	let graph_before = KVStore::read(&wallet_store, "", "", NETWORK_GRAPH_PERSISTENCE_KEY)
		.await
		.expect("the app persisted its graph");

	// The extension: the same keys and store, in claim-only mode, on its own 2-worker runtime, with
	// a chain server that doesn't answer.
	let extension_runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.thread_name("claim-only")
		.enable_all()
		.build()
		.unwrap();
	let mut claim_config = wallet_config.clone();
	claim_config.node_config.claim_only = true;
	let claim_store = ClaimOnlyStore::new(wallet_store.clone());
	let before = process_threads_and_resident_bytes();
	let started_at = Instant::now();
	let wallet = {
		setup_builder!(builder, claim_config.node_config);
		builder.set_chain_source_esplora("http://127.0.0.1:9".to_string(), None);
		builder.set_runtime(extension_runtime.handle().clone()).unwrap();
		let node =
			builder.build_with_store(claim_config.node_entropy, claim_store.clone()).unwrap();
		node.start().unwrap();
		node
	};
	let start_time = started_at.elapsed();
	let after = process_threads_and_resident_bytes();
	assert!(wallet.status().is_running);
	// No fee estimates fetched and no chain sync done since the app's.
	let status = wallet.status();
	assert_eq!(
		status.latest_fee_rate_cache_update_timestamp,
		app_status.latest_fee_rate_cache_update_timestamp
	);
	assert_eq!(
		status.latest_lightning_wallet_sync_timestamp,
		app_status.latest_lightning_wallet_sync_timestamp
	);
	assert!(wallet.network_graph().list_channels().is_empty());
	assert_eq!(extension_runtime.handle().metrics().num_workers(), 2);

	// The provider forwards the payment, and the extension claims it.
	let provider_address = provider.listening_addresses().unwrap().first().unwrap().clone();
	wallet.connect(provider.node_id(), provider_address, false).unwrap();
	let claim_started_at = Instant::now();
	let payment_id = payer.bolt11_payment().send(&invoice, None).unwrap();
	expect_payment_received_event!(wallet, amount_msat);
	let claim_time = claim_started_at.elapsed();
	expect_payment_successful_event!(payer, payment_id, None);

	// It learned no gossip from the provider, whose graph has the payer's channel.
	assert!(!provider.network_graph().list_channels().is_empty());
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert!(wallet.network_graph().list_channels().is_empty());
	assert!(wallet.network_graph().list_nodes().is_empty());

	println!(
		"Claim-only start: {:?}; claim: {:?}; process threads and resident bytes before/after start: {:?} / {:?}; dropped graph/scorer writes so far: {}",
		start_time,
		claim_time,
		before,
		after,
		claim_store.dropped_writes.load(Ordering::Relaxed)
	);

	wallet.stop().unwrap();
	drop(wallet);
	println!(
		"Graph/scorer writes the store wrapper dropped: {}",
		claim_store.dropped_writes.load(Ordering::Relaxed)
	);

	// The same over an Electrum server that doesn't answer: its client isn't even started.
	let wallet = {
		setup_builder!(builder, claim_config.node_config);
		builder.set_chain_source_electrum("tcp://127.0.0.1:9".to_string(), None);
		builder.set_runtime(extension_runtime.handle().clone()).unwrap();
		let node =
			builder.build_with_store(claim_config.node_entropy, claim_store.clone()).unwrap();
		node.start().unwrap();
		node
	};
	assert!(wallet.status().is_running);
	wallet.stop().unwrap();
	drop(wallet);
	extension_runtime.shutdown_background();

	// The app's graph is still the one it wrote.
	let graph_after =
		KVStore::read(&wallet_store, "", "", NETWORK_GRAPH_PERSISTENCE_KEY).await.unwrap();
	assert_eq!(graph_before, graph_after);

	// For comparison: the app's own start, with the chain and the graph.
	let mut app_config: TestConfig = wallet_config.clone();
	app_config.node_config.claim_only = false;
	let before = process_threads_and_resident_bytes();
	let started_at = Instant::now();
	let wallet = common::setup_node_with_store(&chain_source, app_config, wallet_store.clone());
	let start_time = started_at.elapsed();
	let after = process_threads_and_resident_bytes();
	println!(
		"Normal start: {:?}; process threads and resident bytes before/after start: {:?} / {:?}",
		start_time, before, after
	);
	assert!(!wallet.network_graph().list_channels().is_empty());
	wallet.stop().unwrap();
}

/// An unannounced wallet node that routes its onion messages via `lsp`, as the app sets it up.
fn wallet_config_via(lsp: Option<&TestNode>) -> TestConfig {
	let mut config = random_config();
	config.node_config.listening_addresses = None;
	config.node_config.node_alias = None;
	config.node_config.route_messages_via_lsp = lsp.is_some();
	config
}

/// Builds and starts `config`'s node claim-only, around the wallet core's store wrapper, with
/// `lsp` as its liquidity source.
fn start_claim_only(
	chain_source: &TestChainSource, config: &TestConfig, store: ClaimOnlyStore,
	lsp: Option<&TestNode>,
) -> TestNode {
	let mut config = config.clone();
	config.node_config.claim_only = true;
	setup_builder!(builder, config.node_config);
	common::configure_chain_source(chain_source, &mut builder, &config);
	if let Some(lsp) = lsp {
		let address = lsp.listening_addresses().unwrap().first().unwrap().clone();
		builder.add_liquidity_source(lsp.node_id(), address, None, false);
	}
	let node = builder.build_with_store(config.node_entropy, store).unwrap();
	node.start().unwrap();
	node
}

async fn wait_for_graph_channels(node: &TestNode, count: usize) {
	while node.network_graph().list_channels().len() < count {
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

/// A claim-only wallet is paid to its BOLT 12 offer by a payer behind its own LSP (Phoenix behind
/// ACINQ): the payer's reply path starts at that LSP, which the wallet isn't connected to and has
/// no address for. The wallet sends its invoice through its provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn claim_only_wallet_answers_a_bolt12_payer_through_its_provider() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	let payer_lsp = setup_node(&chain_source, random_config());
	let provider = setup_node(&chain_source, random_config());
	// The payer reaches the network only through its LSP, too.
	let mut payer_config = wallet_config_via(Some(&payer_lsp));
	payer_config.node_config.route_messages_via_lsp = true;
	let payer = {
		setup_builder!(builder, payer_config.node_config);
		common::configure_chain_source(&chain_source, &mut builder, &payer_config);
		let address = payer_lsp.listening_addresses().unwrap().first().unwrap().clone();
		builder.add_liquidity_source(payer_lsp.node_id(), address, None, false);
		let node = builder
			.build_with_store(
				payer_config.node_entropy,
				TestSyncStore::new(payer_config.node_config.storage_dir_path.clone().into()),
			)
			.unwrap();
		node.start().unwrap();
		node
	};
	let wallet_config = wallet_config_via(Some(&provider));
	let wallet_store =
		TestSyncStore::new(wallet_config.node_config.storage_dir_path.clone().into());
	let wallet =
		common::setup_node_with_store(&chain_source, wallet_config.clone(), wallet_store.clone());

	let addresses = vec![
		payer.onchain_payment().new_address().unwrap(),
		payer_lsp.onchain_payment().new_address().unwrap(),
		wallet.onchain_payment().new_address().unwrap(),
	];
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(2_000_000),
	)
	.await;
	for node in [&payer, &payer_lsp, &wallet] {
		node.sync_wallets().unwrap();
	}

	// payer -- payer_lsp (unannounced), payer_lsp -- provider (announced), wallet -- provider
	// (unannounced, half pushed so the wallet can receive).
	open_channel(&payer, &payer_lsp, 1_000_000, false, &electrsd).await;
	open_channel(&payer_lsp, &provider, 1_000_000, true, &electrsd).await;
	open_channel_push_amt(&wallet, &provider, 1_000_000, Some(500_000_000), false, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &payer_lsp, &provider, &wallet] {
		node.sync_wallets().unwrap();
	}
	expect_channel_ready_event!(payer, payer_lsp.node_id());
	expect_channel_ready_event!(payer_lsp, payer.node_id());
	expect_channel_ready_event!(payer_lsp, provider.node_id());
	expect_channel_ready_event!(provider, payer_lsp.node_id());
	expect_channel_ready_event!(wallet, provider.node_id());
	expect_channel_ready_event!(provider, wallet.node_id());
	// The payer routes over the announced channel.
	wait_for_graph_channels(&payer, 1).await;

	// The app shows an offer and closes; the extension starts claim-only, with no graph.
	let amount_msat = 40_000_000;
	let offer = wallet.bolt12_payment().receive(amount_msat, "claim-only", None, None).unwrap();
	wallet.stop().unwrap();
	drop(wallet);
	let wallet = start_claim_only(
		&chain_source,
		&wallet_config,
		ClaimOnlyStore::new(wallet_store.clone()),
		Some(&provider),
	);
	assert!(wallet.network_graph().list_nodes().is_empty());
	let provider_address = provider.listening_addresses().unwrap().first().unwrap().clone();
	wallet.connect(provider.node_id(), provider_address, false).unwrap();

	let payment_id = payer.bolt12_payment().send(&offer, None, None, None).unwrap();
	expect_payment_received_event!(wallet, amount_msat);
	expect_payment_successful_event!(payer, payment_id, None);
	// The wallet never connected to the payer's LSP: everything went through its provider.
	assert!(wallet.list_peers().iter().all(|peer| peer.node_id != payer_lsp.node_id()));

	wallet.stop().unwrap();
}

/// Builds and starts a wallet node (not claim-only) for `config`, with `lsp` as its liquidity
/// source.
fn start_wallet(
	chain_source: &TestChainSource, config: &TestConfig, store: TestSyncStore, lsp: &TestNode,
) -> TestNode {
	setup_builder!(builder, config.node_config);
	common::configure_chain_source(chain_source, &mut builder, config);
	let address = lsp.listening_addresses().unwrap().first().unwrap().clone();
	builder.add_liquidity_source(lsp.node_id(), address, None, false);
	let node = builder.build_with_store(config.node_entropy, store).unwrap();
	node.start().unwrap();
	node
}

fn has_node_announcement(graph_of: &TestNode, node: &TestNode) -> bool {
	graph_of
		.network_graph()
		.node(&NodeId::from_pubkey(&node.node_id()))
		.map_or(false, |info| info.announcement_info.is_some())
}

/// A wallet pays an offer whose introduction node its provider has no channel with and isn't
/// connected to. The provider intercepts the wallet's invoice request for that node, connects to
/// it from the addresses in its graph, and forwards the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn provider_connects_to_forward_a_wallets_onion_message() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	let mut provider_config = random_config();
	provider_config.async_payments_role = Some(AsyncPaymentsRole::Server);
	let provider = setup_node(&chain_source, provider_config);
	let hop = setup_node(&chain_source, random_config());
	let recipient = setup_node(&chain_source, random_config());
	let wallet_config = wallet_config_via(Some(&provider));
	let wallet = start_wallet(
		&chain_source,
		&wallet_config,
		TestSyncStore::new(wallet_config.node_config.storage_dir_path.clone().into()),
		&provider,
	);

	let addresses = vec![
		wallet.onchain_payment().new_address().unwrap(),
		provider.onchain_payment().new_address().unwrap(),
		hop.onchain_payment().new_address().unwrap(),
	];
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		addresses,
		Amount::from_sat(2_000_000),
	)
	.await;
	for node in [&wallet, &provider, &hop] {
		node.sync_wallets().unwrap();
	}

	// wallet -- provider (unannounced), provider -- hop -- recipient (announced). The provider
	// shares no channel with the recipient.
	open_channel(&wallet, &provider, 1_000_000, false, &electrsd).await;
	open_channel(&provider, &hop, 1_000_000, true, &electrsd).await;
	open_channel(&hop, &recipient, 1_000_000, true, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&wallet, &provider, &hop, &recipient] {
		node.sync_wallets().unwrap();
	}
	expect_channel_ready_event!(wallet, provider.node_id());
	expect_channel_ready_event!(provider, wallet.node_id());
	expect_channel_ready_event!(provider, hop.node_id());
	expect_channel_ready_event!(hop, provider.node_id());
	expect_channel_ready_event!(hop, recipient.node_id());
	expect_channel_ready_event!(recipient, hop.node_id());

	// The provider has the recipient's address from gossip; the wallet has the channels.
	while !has_node_announcement(&provider, &recipient) {
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	wait_for_graph_channels(&wallet, 2).await;
	assert!(provider.list_peers().iter().all(|peer| peer.node_id != recipient.node_id()));

	let amount_msat = 30_000_000;
	let offer = recipient.bolt12_payment().receive(amount_msat, "forwarded", None, None).unwrap();
	let payment_id = wallet.bolt12_payment().send(&offer, None, None, None).unwrap();
	expect_payment_received_event!(recipient, amount_msat);
	expect_payment_successful_event!(wallet, payment_id, None);
	assert!(provider.list_peers().iter().any(|peer| peer.node_id == recipient.node_id()));
	// The wallet itself never dialled the recipient.
	assert!(wallet.list_peers().iter().all(|peer| peer.node_id != recipient.node_id()));

	wallet.stop().unwrap();
}
