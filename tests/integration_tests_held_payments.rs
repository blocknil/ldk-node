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

use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use common::{
	generate_blocks_and_wait, open_channel, open_channel_no_wait, premine_and_distribute_funds,
	random_config, setup_bitcoind_and_electrsd, setup_node, TestChainSource, TestNode,
	TestStoreType,
};
use ldk_node::{Event, UserChannelId};

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
