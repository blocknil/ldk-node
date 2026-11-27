// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: app messages, our own peer messages beside LSPS, between real nodes on regtest.
//! A provider answers a wallet's requests and notifies it on connect; a node without a handler
//! ignores them; and LSPS2 keeps working after app messages from the same peer.

#![cfg(not(feature = "uniffi"))]

mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use common::{
	expect_channel_pending_event, expect_channel_ready_event, expect_payment_received_event,
	expect_payment_successful_event, generate_blocks_and_wait, open_channel,
	premine_and_distribute_funds, random_config, setup_bitcoind_and_electrsd, setup_builder,
};
use electrsd::ElectrsD;
use ldk_node::config::EsploraSyncConfig;
use ldk_node::liquidity::{LSPS2ServiceConfig, DEFAULT_OPENING_FEE_PARAMS_LIFETIME_SECS};
use ldk_node::{AppMessageHandler, Builder, Event, Node, NodeError, MAX_APP_MESSAGE_LEN};
use lightning::ln::msgs::{DecodeError, Init, LightningError};
use lightning::ln::peer_handler::{
	CustomMessageHandler, ErroringMessageHandler, IgnoringMessageHandler, MessageHandler,
	PeerManager,
};
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use lightning_types::features::{InitFeatures, NodeFeatures};
use tokio::sync::mpsc;

#[derive(Debug, PartialEq)]
enum Seen {
	Received(PublicKey, String),
	Connected(PublicKey, bool),
	Disconnected(PublicKey),
}

/// Records what it is told. As a provider (`node` set), it also answers each request and sends a
/// notification to each peer that connects with app messages, from inside the callbacks, as
/// Blocknil's provider does.
struct TestHandler {
	node: OnceLock<Arc<Node>>,
	seen: mpsc::UnboundedSender<Seen>,
}

impl AppMessageHandler for TestHandler {
	fn received(&self, peer: PublicKey, payload: String) {
		if let Some(node) = self.node.get() {
			// A long payload is answered with its length, so the answer fits too.
			let answer = if payload.len() > 1000 {
				format!("{} bytes", payload.len())
			} else {
				format!("answer to {}", payload)
			};
			node.send_app_message(peer, answer).unwrap();
		}
		let _ = self.seen.send(Seen::Received(peer, payload));
	}

	fn connected(&self, peer: PublicKey, supports_app_messages: bool) {
		if let (Some(node), true) = (self.node.get(), supports_app_messages) {
			node.send_app_message(peer, "notification".to_string()).unwrap();
		}
		let _ = self.seen.send(Seen::Connected(peer, supports_app_messages));
	}

	fn disconnected(&self, peer: PublicKey) {
		let _ = self.seen.send(Seen::Disconnected(peer));
	}
}

fn handler() -> (Arc<TestHandler>, mpsc::UnboundedReceiver<Seen>) {
	let (seen, rx) = mpsc::unbounded_channel();
	(Arc::new(TestHandler { node: OnceLock::new(), seen }), rx)
}

fn esplora(electrsd: &ElectrsD) -> (String, EsploraSyncConfig) {
	let mut sync_config = EsploraSyncConfig::default();
	sync_config.background_sync_config = None;
	(format!("http://{}", electrsd.esplora_url.as_ref().unwrap()), sync_config)
}

/// A started node; `handler` is set as its app message handler, and as a provider when
/// `provider`.
fn node(
	electrsd: &ElectrsD, handler: Option<&Arc<TestHandler>>, provider: bool,
	setup: impl FnOnce(&mut Builder),
) -> Arc<Node> {
	let (esplora_url, sync_config) = esplora(electrsd);
	let config = random_config();
	setup_builder!(builder, config.node_config);
	builder.set_chain_source_esplora(esplora_url, Some(sync_config));
	if let Some(handler) = handler {
		builder.set_app_message_handler(Arc::clone(handler) as Arc<dyn AppMessageHandler>);
	}
	setup(&mut builder);
	let node = Arc::new(builder.build(config.node_entropy.into()).unwrap());
	if provider {
		assert!(handler.unwrap().node.set(Arc::clone(&node)).is_ok());
	}
	node.start().unwrap();
	node
}

async fn next(rx: &mut mpsc::UnboundedReceiver<Seen>) -> Seen {
	tokio::time::timeout(Duration::from_secs(30), rx.recv())
		.await
		.expect("timed out waiting for an app message callback")
		.expect("handler gone")
}

/// Waits for `want`, skipping the connect and disconnect callbacks that come before it.
async fn next_received(rx: &mut mpsc::UnboundedReceiver<Seen>, from: PublicKey) -> String {
	loop {
		match next(rx).await {
			Seen::Received(peer, payload) if peer == from => return payload,
			other => println!("skipping {:?}", other),
		}
	}
}

fn connect(from: &Node, to: &Node) {
	let address = to.listening_addresses().unwrap().first().unwrap().clone();
	from.connect(to.node_id(), address, false).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn app_messages_request_answer_and_notification_on_connect() {
	let (_bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let (provider_handler, mut provider_seen) = handler();
	let (wallet_handler, mut wallet_seen) = handler();
	let provider = node(&electrsd, Some(&provider_handler), true, |_| {});
	let wallet = node(&electrsd, Some(&wallet_handler), false, |_| {});
	let plain = node(&electrsd, None, false, |_| {});

	// Not connected yet: nothing to send to.
	assert_eq!(
		wallet.send_app_message(provider.node_id(), "early".into()),
		Err(NodeError::ConnectionFailed)
	);

	// On connect, both sides see the other's bit, and the provider's notification arrives.
	connect(&wallet, &provider);
	assert_eq!(next(&mut provider_seen).await, Seen::Connected(wallet.node_id(), true));
	assert_eq!(next(&mut wallet_seen).await, Seen::Connected(provider.node_id(), true));
	assert_eq!(next_received(&mut wallet_seen, provider.node_id()).await, "notification");
	assert!(wallet.peer_has_app_messages(&provider.node_id()));
	assert!(provider.peer_has_app_messages(&wallet.node_id()));

	// A request and its answer, the answer sent from inside the provider's callback.
	let request = r#"{"jsonrpc":"2.0","method":"blocknil.get_quotes","params":{},"id":"1"}"#;
	wallet.send_app_message(provider.node_id(), request.into()).unwrap();
	assert_eq!(next_received(&mut provider_seen, wallet.node_id()).await, request);
	assert_eq!(
		next_received(&mut wallet_seen, provider.node_id()).await,
		format!("answer to {}", request)
	);

	// The largest payload goes through whole; one byte more, or a zero byte, isn't sent.
	let largest = "a".repeat(MAX_APP_MESSAGE_LEN);
	wallet.send_app_message(provider.node_id(), largest.clone()).unwrap();
	assert_eq!(next_received(&mut provider_seen, wallet.node_id()).await, largest);
	assert_eq!(next_received(&mut wallet_seen, provider.node_id()).await, "65533 bytes");
	assert_eq!(
		wallet.send_app_message(provider.node_id(), "a".repeat(MAX_APP_MESSAGE_LEN + 1)),
		Err(NodeError::InvalidAppMessage)
	);
	assert_eq!(
		wallet.send_app_message(provider.node_id(), "a\0".into()),
		Err(NodeError::InvalidAppMessage)
	);

	// After a reconnect, the notification comes again.
	wallet.disconnect(provider.node_id()).unwrap();
	loop {
		if next(&mut wallet_seen).await == Seen::Disconnected(provider.node_id()) {
			break;
		}
	}
	assert!(!wallet.peer_has_app_messages(&provider.node_id()));
	connect(&wallet, &provider);
	assert_eq!(next_received(&mut wallet_seen, provider.node_id()).await, "notification");

	// A node without a handler: no bit either way, and what we send it is ignored, the
	// connection kept.
	connect(&wallet, &plain);
	loop {
		match next(&mut wallet_seen).await {
			Seen::Connected(peer, supports) if peer == plain.node_id() => {
				assert!(!supports);
				break;
			},
			other => println!("skipping {:?}", other),
		}
	}
	assert!(!wallet.peer_has_app_messages(&plain.node_id()));
	// The plain node still learns from the wallet's `Init` that the wallet takes them.
	assert!(plain.peer_has_app_messages(&wallet.node_id()));
	wallet.send_app_message(plain.node_id(), request.into()).unwrap();
	connect(&provider, &plain);
	loop {
		match next(&mut provider_seen).await {
			Seen::Connected(peer, supports) if peer == plain.node_id() => {
				assert!(!supports);
				break;
			},
			other => println!("skipping {:?}", other),
		}
	}
	tokio::time::sleep(Duration::from_secs(2)).await;
	let connected = |from: &Node, to: &Node| {
		from.list_peers().iter().any(|p| p.node_id == to.node_id() && p.is_connected)
	};
	assert!(connected(&wallet, &plain) && connected(&plain, &wallet));
	assert!(connected(&wallet, &provider));

	// And the provider sent no notification to a peer without the bit: the wallet's next
	// message from it is the answer to this one.
	wallet.send_app_message(provider.node_id(), "last".into()).unwrap();
	assert_eq!(next_received(&mut wallet_seen, provider.node_id()).await, "answer to last");

	provider.stop().unwrap();
	wallet.stop().unwrap();
	plain.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn lsps2_jit_receive_works_after_app_messages_from_the_same_peer() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();

	let channel_opening_fee_ppm = 10_000;
	let lsps2_service_config = LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		channel_opening_fee_ppm,
		channel_over_provisioning_ppm: 100_000,
		max_payment_size_msat: 1_000_000_000,
		min_payment_size_msat: 0,
		min_channel_lifetime: 100,
		min_channel_opening_fee_msat: 0,
		max_client_to_self_delay: 1024,
		client_trusts_lsp: false,
		disable_client_reserve: false,
		opening_fee_params_lifetime_secs: DEFAULT_OPENING_FEE_PARAMS_LIFETIME_SECS,
		opening_cost: None,
	};
	let (service_handler, mut service_seen) = handler();
	let service = node(&electrsd, Some(&service_handler), true, |b| {
		b.enable_liquidity_provider(lsps2_service_config);
	});
	let service_addr = service.listening_addresses().unwrap().first().unwrap().clone();
	let (client_handler, mut client_seen) = handler();
	let client = node(&electrsd, Some(&client_handler), false, |b| {
		b.add_liquidity_source(service.node_id(), service_addr.clone(), None, true);
	});
	let payer = node(&electrsd, None, false, |_| {});

	// Before any LSPS2 request, the client sends the service what LSPS's own handler would
	// take as a reason to ignore it for the rest of the connection: not JSON, and an LSPS2
	// method and a `blocknil.` one it doesn't know. On our type they reach the app handler
	// and nothing else.
	connect(&client, &service);
	assert_eq!(next_received(&mut client_seen, service.node_id()).await, "notification");
	let odd = [
		"not json {".to_string(),
		r#"{"jsonrpc":"2.0","method":"lsps2.get_info","params":{},"id":"x"}"#.to_string(),
		r#"{"jsonrpc":"2.0","method":"blocknil.unknown","params":{},"id":"y"}"#.to_string(),
	];
	for payload in &odd {
		client.send_app_message(service.node_id(), payload.clone()).unwrap();
		assert_eq!(&next_received(&mut service_seen, client.node_id()).await, payload);
		assert_eq!(
			next_received(&mut client_seen, service.node_id()).await,
			format!("answer to {}", payload)
		);
	}

	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![
			service.onchain_payment().new_address().unwrap(),
			client.onchain_payment().new_address().unwrap(),
			payer.onchain_payment().new_address().unwrap(),
		],
		Amount::from_sat(10_000_000),
	)
	.await;
	service.sync_wallets().unwrap();
	client.sync_wallets().unwrap();
	payer.sync_wallets().unwrap();
	open_channel(&payer, &service, 5_000_000, false, &electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	service.sync_wallets().unwrap();
	payer.sync_wallets().unwrap();
	expect_channel_ready_event!(payer, service.node_id());
	expect_channel_ready_event!(service, payer.node_id());

	// LSPS2 between the same two nodes, on the same connection: a JIT receive.
	let description =
		Bolt11InvoiceDescription::Direct(Description::new(String::from("jit")).unwrap());
	let jit_amount_msat = 100_000_000;
	let invoice = client
		.bolt11_payment()
		.receive_via_jit_channel(jit_amount_msat, &description.into(), 1024)
		.unwrap();
	let payment_id = payer.bolt11_payment().send(&invoice, None).unwrap();
	expect_channel_pending_event!(service, client.node_id());
	expect_channel_ready_event!(service, client.node_id());
	expect_channel_pending_event!(client, service.node_id());
	expect_channel_ready_event!(client, service.node_id());
	expect_payment_successful_event!(payer, payment_id, None);
	let fee_msat = jit_amount_msat * channel_opening_fee_ppm as u64 / 1_000_000;
	expect_payment_received_event!(client, jit_amount_msat - fee_msat);

	// And app messages still go both ways afterwards.
	client.send_app_message(service.node_id(), "after".into()).unwrap();
	assert_eq!(next_received(&mut client_seen, service.node_id()).await, "answer to after");

	service.stop().unwrap();
	client.stop().unwrap();
	payer.stop().unwrap();
}

/// A frame of any type with any bytes: what a peer outside our code can put on the wire.
#[derive(Debug)]
struct RawFrame {
	ty: u16,
	bytes: Vec<u8>,
}

impl Type for RawFrame {
	fn type_id(&self) -> u16 {
		self.ty
	}
}

impl Writeable for RawFrame {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
		w.write_all(&self.bytes)
	}
}

/// The custom message handler of a bare LDK `PeerManager`: sends whatever frames the test queues,
/// keeps every 37913 and 40213 frame it gets, and announces the *required* twin of our bit (412).
#[derive(Default)]
struct RawPeer {
	out: Mutex<Vec<(PublicKey, RawFrame)>>,
	got: Mutex<Vec<(u16, Vec<u8>)>>,
}

impl CustomMessageReader for RawPeer {
	type CustomMessage = RawFrame;
	fn read<RD: LengthLimitedRead>(
		&self, ty: u16, buffer: &mut RD,
	) -> Result<Option<RawFrame>, DecodeError> {
		if ty != 37913 && ty != ldk_node::APP_MESSAGE_TYPE {
			return Ok(None);
		}
		let mut bytes = vec![0u8; buffer.remaining_bytes() as usize];
		buffer.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
		Ok(Some(RawFrame { ty, bytes }))
	}
}

impl CustomMessageHandler for RawPeer {
	fn handle_custom_message(&self, msg: RawFrame, _: PublicKey) -> Result<(), LightningError> {
		self.got.lock().unwrap().push((msg.ty, msg.bytes));
		Ok(())
	}
	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, RawFrame)> {
		std::mem::take(&mut *self.out.lock().unwrap())
	}
	fn peer_disconnected(&self, _: PublicKey) {}
	fn peer_connected(&self, _: PublicKey, _: &Init, _: bool) -> Result<(), ()> {
		Ok(())
	}
	fn provided_node_features(&self) -> NodeFeatures {
		NodeFeatures::empty()
	}
	fn provided_init_features(&self, _: PublicKey) -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_required_custom_bit(ldk_node::APP_MESSAGES_FEATURE_BIT - 1).unwrap();
		features
	}
}

struct QuietLogger;

impl Logger for QuietLogger {
	fn log(&self, _: Record) {}
}

fn is_connected(node: &Node, peer: PublicKey) -> bool {
	node.list_peers().iter().any(|p| p.node_id == peer && p.is_connected)
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
	for _ in 0..300 {
		if done() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	panic!("timed out waiting for {}", what);
}

/// The fork's safety claim, at the wire: a peer outside our code sends 40213 frames our API would
/// never send (a zero byte, bytes that aren't UTF-8) and an empty one. The service drops the first
/// two without a reply, answers the empty one, keeps the peer connected, and still answers an LSPS2
/// `get_info` from it on 37913 afterwards. The peer announces only the required twin (412) of our
/// bit, which counts as support.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_bad_app_frames_keep_the_peer_connected_and_lsps2_answering() {
	let (_bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let lsps2_service_config = LSPS2ServiceConfig {
		require_token: None,
		advertise_service: false,
		channel_opening_fee_ppm: 10_000,
		channel_over_provisioning_ppm: 100_000,
		max_payment_size_msat: 1_000_000_000,
		min_payment_size_msat: 0,
		min_channel_lifetime: 100,
		min_channel_opening_fee_msat: 0,
		max_client_to_self_delay: 1024,
		client_trusts_lsp: false,
		disable_client_reserve: false,
		opening_fee_params_lifetime_secs: DEFAULT_OPENING_FEE_PARAMS_LIFETIME_SECS,
		opening_cost: None,
	};
	let (service_handler, mut service_seen) = handler();
	let service = node(&electrsd, Some(&service_handler), true, |b| {
		b.enable_liquidity_provider(lsps2_service_config);
	});

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let keys = Arc::new(KeysManager::new(&[9; 32], now.as_secs(), now.subsec_nanos(), true));
	let raw_id = keys.get_node_id(Recipient::Node).unwrap();
	let raw = Arc::new(RawPeer::default());
	let peer_manager = Arc::new(PeerManager::new(
		MessageHandler {
			chan_handler: Arc::new(ErroringMessageHandler::new()),
			route_handler: Arc::new(IgnoringMessageHandler {}),
			onion_message_handler: Arc::new(IgnoringMessageHandler {}),
			custom_message_handler: Arc::clone(&raw),
			send_only_message_handler: Arc::new(IgnoringMessageHandler {}),
		},
		now.as_secs() as u32,
		&[3; 32],
		Arc::new(QuietLogger),
		Arc::clone(&keys),
	));
	let address = match service.listening_addresses().unwrap().first().unwrap() {
		lightning::ln::msgs::SocketAddress::TcpIpV4 { addr, port } => {
			std::net::SocketAddr::from((*addr, *port))
		},
		other => panic!("{:?}", other),
	};
	let connection = lightning_net_tokio::connect_outbound(
		Arc::clone(&peer_manager),
		service.node_id(),
		address,
	)
	.await
	.expect("connect");
	tokio::spawn(connection);
	assert_eq!(next(&mut service_seen).await, Seen::Connected(raw_id, true));
	wait_until("the service to list the raw peer", || is_connected(&service, raw_id)).await;
	// The raw peer must have the service's `Init` before it sends, or its `PeerManager` drops
	// what it queues. The service's notification on connect comes after its `Init`.
	wait_until("the service's notification at the raw peer", || {
		raw.got
			.lock()
			.unwrap()
			.iter()
			.any(|(ty, b)| *ty == ldk_node::APP_MESSAGE_TYPE && b.as_slice() == b"notification")
	})
	.await;

	let send = |ty: u16, bytes: &[u8]| {
		raw.out.lock().unwrap().push((service.node_id(), RawFrame { ty, bytes: bytes.to_vec() }));
		peer_manager.process_events();
	};
	send(ldk_node::APP_MESSAGE_TYPE, b"zero\0byte");
	send(ldk_node::APP_MESSAGE_TYPE, &[0xff, 0xfe, 0xfd]);
	send(ldk_node::APP_MESSAGE_TYPE, b"");
	send(ldk_node::APP_MESSAGE_TYPE, b"hello");
	// The handler sees only the empty payload and "hello", in order: the two bad ones are dropped.
	assert_eq!(next_received(&mut service_seen, raw_id).await, "");
	assert_eq!(next_received(&mut service_seen, raw_id).await, "hello");

	send(37913, br#"{"jsonrpc":"2.0","method":"lsps2.get_info","params":{},"id":"t1"}"#);
	let got = |want: &dyn Fn(&(u16, Vec<u8>)) -> bool| raw.got.lock().unwrap().iter().any(want);
	wait_until("the LSPS2 answer", || {
		peer_manager.process_events();
		got(&|(ty, bytes)| {
			let text = String::from_utf8_lossy(bytes);
			*ty == 37913
				&& text.contains(r#""id":"t1""#)
				&& text.contains("opening_fee_params_menu")
		})
	})
	.await;
	let app_answers: Vec<String> = raw
		.got
		.lock()
		.unwrap()
		.iter()
		.filter(|(ty, _)| *ty == ldk_node::APP_MESSAGE_TYPE)
		.map(|(_, b)| String::from_utf8(b.clone()).unwrap())
		.collect();
	// The notification on connect, then an answer to each payload the handler saw.
	assert_eq!(app_answers, vec!["notification", "answer to ", "answer to hello"]);
	assert!(is_connected(&service, raw_id));
	assert!(peer_manager.peer_by_node_id(&service.node_id()).is_some());

	peer_manager.disconnect_all_peers();
	service.stop().unwrap();
}

/// Panics in every callback.
struct Panicker;

impl AppMessageHandler for Panicker {
	fn received(&self, _: PublicKey, _: String) {
		panic!("received");
	}
	fn connected(&self, _: PublicKey, _: bool) {
		panic!("connected");
	}
	fn disconnected(&self, _: PublicKey) {
		panic!("disconnected");
	}
}

/// A handler that panics in every callback leaves the node and the peer working: connect, a
/// message, a disconnect and a reconnect all go through, and the node still lists its peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_panicking_handler_leaves_the_node_and_the_peer_working() {
	let (_bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let (esplora_url, sync_config) = esplora(&electrsd);
	let config = random_config();
	setup_builder!(builder, config.node_config);
	builder.set_chain_source_esplora(esplora_url, Some(sync_config));
	builder.set_app_message_handler(Arc::new(Panicker));
	let panicky = Arc::new(builder.build(config.node_entropy.into()).unwrap());
	panicky.start().unwrap();
	let (wallet_handler, mut wallet_seen) = handler();
	let wallet = node(&electrsd, Some(&wallet_handler), false, |_| {});

	for round in 0..2 {
		connect(&wallet, &panicky);
		assert_eq!(next(&mut wallet_seen).await, Seen::Connected(panicky.node_id(), true));
		wallet.send_app_message(panicky.node_id(), format!("round {}", round)).unwrap();
		tokio::time::sleep(Duration::from_secs(1)).await;
		assert!(is_connected(&panicky, wallet.node_id()), "round {}", round);
		assert!(is_connected(&wallet, panicky.node_id()), "round {}", round);
		assert!(panicky.peer_has_app_messages(&wallet.node_id()));
		wallet.disconnect(panicky.node_id()).unwrap();
		assert_eq!(next(&mut wallet_seen).await, Seen::Disconnected(panicky.node_id()));
		wait_until("the panicking node to see the disconnect", || {
			!is_connected(&panicky, wallet.node_id())
		})
		.await;
	}
	// And it can still dial out itself.
	connect(&panicky, &wallet);
	assert_eq!(next(&mut wallet_seen).await, Seen::Connected(panicky.node_id(), true));

	panicky.stop().unwrap();
	wallet.stop().unwrap();
}
