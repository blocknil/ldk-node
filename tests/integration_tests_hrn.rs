// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

#![cfg(hrn_tests)]

mod common;

use std::str::FromStr;

use bitcoin::Amount;
use common::{
	expect_channel_ready_event, expect_payment_successful_event, generate_blocks_and_wait,
	open_channel, premine_and_distribute_funds, random_chain_source, random_config,
	setup_bitcoind_and_electrsd, setup_node, setup_two_nodes, TestChainSource,
};
use ldk_node::config::{HRNResolverConfig, HumanReadableNamesConfig};
use ldk_node::payment::UnifiedPaymentResult;
use ldk_node::{Event, NameResolutionError};
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::msgs::SocketAddress;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn unified_send_to_hrn() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);

	let (node_a, node_b) = setup_two_nodes(&chain_source, false, false);

	let address_a = node_a.onchain_payment().new_address().unwrap();
	let premined_sats = 5_000_000;

	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![address_a],
		Amount::from_sat(premined_sats),
	)
	.await;

	node_a.sync_wallets().unwrap();
	open_channel(&node_a, &node_b, 4_000_000, true, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;

	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());

	// Wait until node_b broadcasts a node announcement
	while node_b.status().latest_node_announcement_broadcast_timestamp.is_none() {
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}

	// Sleep to make sure the node announcement propagates
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;

	let test_offer = node_b.bolt12_payment().receive(1000000, "test offer", None, None).unwrap();

	let hrn_str = "matt@mattcorallo.com";

	let unified_handler = node_a.unified_payment();
	unified_handler.set_test_offer(test_offer);

	let offer_payment_id: PaymentId =
		match unified_handler.send(&hrn_str, Some(1000000), None).await {
			Ok(UnifiedPaymentResult::Bolt12 { payment_id }) => {
				println!("\nBolt12 payment sent successfully with PaymentID: {:?}", payment_id);
				payment_id
			},
			Ok(UnifiedPaymentResult::Bolt11 { payment_id: _ }) => {
				panic!("Expected Bolt12 payment but got Bolt11");
			},
			Ok(UnifiedPaymentResult::Onchain { txid: _ }) => {
				panic!("Expected Bolt12 payment but got On-chain transaction");
			},
			Err(e) => {
				panic!("Expected Bolt12 payment but got error: {:?}", e);
			},
		};

	expect_payment_successful_event!(node_a, offer_payment_id, None);
}

/// Blocknil: a name that has a BIP 353 record. Like the test above, these tests look it up on the
/// internet, through Google Public DNS.
const BIP353_NAME: &str = "matt@mattcorallo.com";

fn dns_resolution(enable_hrn_resolution_service: bool) -> HumanReadableNamesConfig {
	HumanReadableNamesConfig {
		resolution_config: HRNResolverConfig::Dns {
			dns_server_address: SocketAddress::from_str("8.8.8.8:53").unwrap(),
			enable_hrn_resolution_service,
		},
	}
}

/// Blocknil: `Node::resolve_name` resolves a name on its own, without paying it, and hands back
/// the record's URI for the wallet to check.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn resolve_name_returns_the_records_uri() {
	let (_bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);
	let mut config = random_config();
	config.node_config.hrn_config = dns_resolution(false);
	let node = setup_node(&chain_source, config);

	let uri = node.resolve_name(BIP353_NAME).unwrap();
	assert!(uri.starts_with("bitcoin:"), "{uri}");
	assert!(uri.contains("lno="), "{uri}");
	assert!(matches!(node.resolve_name("not a name"), Err(NameResolutionError::Failed(_))));

	node.stop().unwrap();
	assert_eq!(node.resolve_name(BIP353_NAME), Err(NameResolutionError::NotRunning));
}
