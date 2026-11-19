// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>.

//! Blocknil spike: held payments and splice on arrival on rust-lightning 0.3's interception
//! flags, with no hold SCIDs. Payer -> provider (LSP) -> customer, on regtest.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use bitcoin::Amount;
use common::{
	generate_blocks_and_wait, open_channel, open_channel_push_amt, premine_and_distribute_funds,
	random_config, setup_bitcoind_and_electrsd, setup_node, TestChainSource, TestNode,
};
use ldk_node::held_payments::ShortOfRoom;
use ldk_node::Event;
use lightning_invoice::{Bolt11InvoiceDescription, Description};

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

struct Setup {
	bitcoind: electrsd::corepc_node::Node,
	electrsd: electrsd::ElectrsD,
	payer: TestNode,
	provider: TestNode,
	customer: TestNode,
}

/// The payer has a 1M channel to the provider; the provider a channel of `customer_channel_sats`
/// to the customer. The provider intercepts every forward to a private channel and locks its own
/// splices at once; the customer locks splices it didn't fund at once.
async fn setup(customer_channel_sats: u64) -> Setup {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);

	let payer = setup_node(&chain_source, random_config());
	let mut provider_config = random_config();
	provider_config.node_config.hold_private_forwards = true;
	provider_config.node_config.outbound_splice_min_depth = Some(0);
	let provider = setup_node(&chain_source, provider_config);
	let mut customer_config = random_config();
	customer_config.node_config.inbound_splice_min_depth = Some(0);
	let customer = setup_node(&chain_source, customer_config);

	let payer_address = payer.onchain_payment().new_address().unwrap();
	let provider_address = provider.onchain_payment().new_address().unwrap();
	let provider_address_2 = provider.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![payer_address, provider_address, provider_address_2],
		Amount::from_sat(2_000_000),
	)
	.await;
	payer.sync_wallets().unwrap();
	provider.sync_wallets().unwrap();

	open_channel(&payer, &provider, 1_000_000, false, &electrsd).await;
	open_channel_push_amt(&provider, &customer, customer_channel_sats, None, false, &electrsd)
		.await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	for node in [&payer, &provider, &customer] {
		node.sync_wallets().unwrap();
	}
	let is_ready = |e: &Event| matches!(e, Event::ChannelReady { .. });
	wait_for(&payer, "the payer's channel", is_ready).await;
	wait_for(&provider, "the provider's first channel", is_ready).await;
	wait_for(&provider, "the provider's second channel", is_ready).await;
	wait_for(&customer, "the customer's channel", is_ready).await;

	Setup { bitcoind, electrsd, payer, provider, customer }
}

fn invoice(customer: &TestNode, amount_msat: u64) -> lightning_invoice::Bolt11Invoice {
	let description =
		Bolt11InvoiceDescription::Direct(Description::new("spike".to_string()).unwrap());
	customer.bolt11_payment().receive(amount_msat, &description.into(), 3600).unwrap()
}

/// LDK's own invoices cap the route hint at the channel's current HTLC maximum, so a payer won't
/// send more than fits today. This one carries no cap.
fn provider_invoice(s: &Setup, amount_msat: u64) -> lightning_invoice::Bolt11Invoice {
	s.customer.receive_via_provider(amount_msat, "spike", 3600, s.provider.node_id()).unwrap()
}

fn is_received(amount_msat: u64) -> impl Fn(&Event) -> bool {
	move |e| matches!(e, Event::PaymentReceived { amount_msat: a, .. } if *a == amount_msat)
}

fn is_successful(e: &Event) -> bool {
	matches!(e, Event::PaymentSuccessful { .. })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn short_of_room_is_spliced_and_forwarded_without_a_block() {
	let s = setup(100_000).await;
	let (tx, rx) = mpsc::channel::<ShortOfRoom>();
	let tx = std::sync::Mutex::new(tx);
	s.provider.set_short_of_room_handler(Arc::new(move |short| {
		tx.lock().unwrap().send(short).unwrap();
	}));

	// A payment that fits goes straight through, although every forward is intercepted now.
	s.payer.bolt11_payment().send(&invoice(&s.customer, 10_000_000), None).unwrap();
	wait_for(&s.customer, "the small payment", is_received(10_000_000)).await;
	wait_for(&s.payer, "the small payment's success", is_successful).await;
	assert!(rx.try_recv().is_err(), "a payment that fits isn't short of room");

	// One too large for the customer's channel is held and reported, once.
	let height_before = s.bitcoind.client.get_block_count().unwrap().0;
	s.payer.bolt11_payment().send(&provider_invoice(&s, 200_000_000), None).unwrap();
	let short = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
		.await
		.unwrap()
		.expect("the provider is told the payment is short of room");
	println!("short of room: {:?}", short);
	assert_eq!(short.customer, s.customer.node_id());
	assert_eq!(short.amount_msat, 200_000_000);
	assert!(short.room_msat < short.amount_msat);
	assert_eq!(s.provider.held_payments().len(), 1);

	// The provider splices its own coins in, and lets the payment go once it fits.
	let channel = s
		.provider
		.list_channels()
		.into_iter()
		.find(|c| c.counterparty.node_id == s.customer.node_id())
		.unwrap();
	s.provider.splice_in(&channel.user_channel_id, s.customer.node_id(), 300_000, None).unwrap();
	assert!(s.provider.set_held_payment_fee(short.intercept_id, 0));

	wait_for(&s.customer, "the large payment", is_received(200_000_000)).await;
	wait_for(&s.payer, "the large payment's success", is_successful).await;
	assert!(s.provider.held_payments().is_empty());
	assert_eq!(
		s.bitcoind.client.get_block_count().unwrap().0,
		height_before,
		"the splice locked with no block mined"
	);

	for node in [&s.payer, &s.provider, &s.customer] {
		node.stop().unwrap();
	}
	drop(s.electrsd);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn refused_payment_fails_back_at_once() {
	let s = setup(100_000).await;
	let (tx, rx) = mpsc::channel::<ShortOfRoom>();
	let tx = std::sync::Mutex::new(tx);
	s.provider.set_short_of_room_handler(Arc::new(move |short| {
		tx.lock().unwrap().send(short).unwrap();
	}));

	s.payer.bolt11_payment().send(&provider_invoice(&s, 200_000_000), None).unwrap();
	let short = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
		.await
		.unwrap()
		.unwrap();
	let started = std::time::Instant::now();
	assert!(s.provider.refuse_held_payment(short.intercept_id));
	wait_for(&s.payer, "the refused payment's failure", |e| {
		matches!(e, Event::PaymentFailed { .. })
	})
	.await;
	assert!(started.elapsed() < Duration::from_secs(20), "failed at once, not at the deadline");
	assert!(s.provider.held_payments().is_empty());

	for node in [&s.payer, &s.provider, &s.customer] {
		node.stop().unwrap();
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn offline_customer_payment_is_held_until_they_are_back() {
	let s = setup(500_000).await;
	let (tx, rx) = mpsc::channel();
	let tx = std::sync::Mutex::new(tx);
	s.provider.set_on_held(Arc::new(move |customer| {
		tx.lock().unwrap().send(customer).unwrap();
	}));

	let invoice = invoice(&s.customer, 50_000_000);
	s.customer.stop().unwrap();
	// Wait for the provider to see the customer gone.
	let customer_id = s.customer.node_id();
	for _ in 0..100 {
		if s.provider.list_peers().iter().all(|p| p.node_id != customer_id || !p.is_connected) {
			break;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	s.payer.bolt11_payment().send(&invoice, None).unwrap();
	let woken = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
		.await
		.unwrap()
		.expect("the provider holds the payment and asks to wake the customer");
	assert_eq!(woken, customer_id);
	assert_eq!(s.provider.held_payments().len(), 1);

	// Back after a few seconds: the payment goes out.
	tokio::time::sleep(Duration::from_secs(3)).await;
	s.customer.start().unwrap();
	wait_for(&s.customer, "the held payment", is_received(50_000_000)).await;
	wait_for(&s.payer, "the held payment's success", is_successful).await;
	assert!(s.provider.held_payments().is_empty());

	for node in [&s.payer, &s.provider, &s.customer] {
		node.stop().unwrap();
	}
}

/// Observes what a BOLT 12 offer payment larger than the customer's room does today: does the
/// customer even produce an invoice (its blinded paths are filtered by inbound capacity)?
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn bolt12_payment_short_of_room() {
	let s = setup(100_000).await;
	let (tx, rx) = mpsc::channel::<ShortOfRoom>();
	let tx = std::sync::Mutex::new(tx);
	s.provider.set_short_of_room_handler(Arc::new(move |short| {
		tx.lock().unwrap().send(short).unwrap();
	}));

	let offer = s.customer.bolt12_payment().receive_variable_amount("spike", None).unwrap();
	s.payer.bolt12_payment().send_using_amount(&offer, 200_000_000, None, None, None).unwrap();

	let short = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
		.await
		.unwrap();
	match short {
		Ok(short) => {
			println!("BOLT12 OBSERVED: intercepted and short of room: {:?}", short);
			let channel = s
				.provider
				.list_channels()
				.into_iter()
				.find(|c| c.counterparty.node_id == s.customer.node_id())
				.unwrap();
			s.provider
				.splice_in(&channel.user_channel_id, s.customer.node_id(), 300_000, None)
				.unwrap();
			assert!(s.provider.set_held_payment_fee(short.intercept_id, 0));
			wait_for(&s.customer, "the offer payment", is_received(200_000_000)).await;
			println!("BOLT12 OBSERVED: received after the splice");
		},
		Err(_) => {
			let event = wait_for(&s.payer, "the offer payment's outcome", |e| {
				matches!(e, Event::PaymentFailed { .. } | Event::PaymentSuccessful { .. })
			})
			.await;
			println!("BOLT12 OBSERVED: never intercepted; the payer saw {:?}", event);
		},
	}

	for node in [&s.payer, &s.provider, &s.customer] {
		node.stop().unwrap();
	}
}
