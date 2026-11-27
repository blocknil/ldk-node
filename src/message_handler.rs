// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{DecodeError, Init, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::util::logger::Logger;
use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};
use lightning_liquidity::lsps0::ser::RawLSPSMessage;
use lightning_types::features::{InitFeatures, NodeFeatures};

use crate::error::Error;
use crate::held_payments::HeldPayments;
use crate::liquidity::LiquiditySource;
use crate::logger::{log_debug, log_error};

// Blocknil patch (app messages): a second custom peer message type beside LSPS's 37913, so the
// user of a node can send and receive its own messages over the Lightning connection. Blocknil's
// provider serves its customers this way instead of over its own HTTP server (bitcoin-wallet #103,
// docs/no-http-customer-service.md, option (b), approved by Esra 2026-11-26).
//
// Why not 37913: `lightning-liquidity` parses every 37913 method into a closed enum, and on an
// unknown one it ignores the sender for the rest of the connection, which would switch off LSPS2
// and LSPS5 with that peer. Our type never reaches the `LiquidityManager`. It is odd, so a node
// that doesn't know it ignores it (BOLT 1), whichever side is older.

/// Blocknil patch: the peer message type that carries app messages (see [`AppMessageHandler`]).
/// Odd and in the custom range, and not in bLIP-2's registry (checked 2026-11-27).
pub const APP_MESSAGE_TYPE: u16 = 40213;

/// Blocknil patch: the optional `Init` feature bit a node sets when it has an
/// [`AppMessageHandler`]. Odd and in the custom range (≥ 256), and not in bLIP-2's registry
/// (checked 2026-11-27). Only sent in `Init`, never in the node announcement.
pub const APP_MESSAGES_FEATURE_BIT: usize = 413;

/// Blocknil patch: the largest app message payload, in bytes: BOLT 8's 65535 bytes less the 2-byte
/// type.
pub const MAX_APP_MESSAGE_LEN: usize = 65533;

/// Blocknil patch: receives the app messages of [`APP_MESSAGE_TYPE`] (set with
/// `Builder::set_app_message_handler`; send with `Node::send_app_message`).
///
/// What reaches it: UTF-8 text of at most [`MAX_APP_MESSAGE_LEN`] bytes, with no zero byte, from a
/// peer whose `Init` set [`APP_MESSAGES_FEATURE_BIT`] (or its even twin). Anything else on our type
/// (bytes that aren't UTF-8, a zero byte, a peer that didn't announce the bit, or no handler set)
/// is dropped without a reply, and the peer stays connected. An empty payload is delivered. `peer`
/// is the node id the peer proved in the BOLT 8 handshake.
///
/// **Callbacks run inside LDK's `PeerManager`:** `received` and `disconnected` under its peer-map
/// lock, `connected` also under that peer's own lock. So each one must:
/// - return quickly, never blocking or waiting on I/O: copy what it needs and hand the work to
///   another thread;
/// - never call `Node::list_peers`, `Node::connect` or `Node::disconnect`: from `connected` they
///   deadlock on those locks. `Node::send_app_message` and `Node::peer_has_app_messages` are safe.
///
/// A panic in a callback is caught and logged, and the call is dropped. That only works when the
/// node is built with `panic = "unwind"`; with `abort`, a panic ends the process anyway.
///
/// **Outbound bound:** messages queued with `Node::send_app_message` wait in an unbounded queue and
/// then in LDK's per-peer buffer, which is also unbounded for these. The caller must bound what it
/// sends (Blocknil's provider: its per-peer limits).
pub trait AppMessageHandler: Send + Sync {
	/// A message from `peer`.
	fn received(&self, peer: PublicKey, payload: String);
	/// `peer` connected; `supports_app_messages` is whether its `Init` sets
	/// [`APP_MESSAGES_FEATURE_BIT`] or its even twin.
	fn connected(&self, peer: PublicKey, supports_app_messages: bool);
	/// `peer` disconnected. Messages still queued for it are dropped.
	fn disconnected(&self, peer: PublicKey);
}

impl fmt::Debug for dyn AppMessageHandler {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("AppMessageHandler")
	}
}

/// Blocknil patch: one app message on the wire: the payload's bytes, without a length prefix
/// (the message's length is the frame's, as for LSPS's `RawLSPSMessage`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppMessage {
	pub(crate) payload: String,
}

impl Type for AppMessage {
	fn type_id(&self) -> u16 {
		APP_MESSAGE_TYPE
	}
}

impl Writeable for AppMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
		w.write_all(self.payload.as_bytes())
	}
}

/// Blocknil patch: what our one custom message handler carries: LSPS as before, or an app message.
#[derive(Debug)]
pub(crate) enum NodeCustomMessage {
	Lsps(RawLSPSMessage),
	App(AppMessage),
}

impl Type for NodeCustomMessage {
	fn type_id(&self) -> u16 {
		match self {
			Self::Lsps(msg) => msg.type_id(),
			Self::App(msg) => msg.type_id(),
		}
	}
}

impl Writeable for NodeCustomMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
		match self {
			Self::Lsps(msg) => msg.write(w),
			Self::App(msg) => msg.write(w),
		}
	}
}

/// Whether `features` set our bit, optional (odd) or required (even), as BOLT 9 reads a pair.
fn sets_app_messages_bit(features: &InitFeatures) -> bool {
	let flags = features.le_flags();
	let even = APP_MESSAGES_FEATURE_BIT - 1;
	[even, APP_MESSAGES_FEATURE_BIT]
		.iter()
		.any(|bit| flags.get(bit / 8).map_or(false, |byte| byte & (1 << (bit % 8)) != 0))
}

/// Blocknil patch: the app message state shared by the custom message handler and the `Node`:
/// the user's handler, the messages waiting for the `PeerManager`, and the connected peers with
/// whether each one supports app messages.
///
/// It also holds the dispatch between LSPS and app messages (the `*_beside` methods), generic over
/// the LSPS handler so it is tested without a node; `NodeCustomMessageHandler` calls them with the
/// `LiquidityManager`.
pub(crate) struct AppMessages {
	handler: Option<Arc<dyn AppMessageHandler>>,
	pending: Mutex<Vec<(PublicKey, AppMessage)>>,
	connected: Mutex<HashMap<PublicKey, bool>>,
	logger: Arc<crate::logger::Logger>,
}

impl AppMessages {
	pub(crate) fn new(
		handler: Option<Arc<dyn AppMessageHandler>>, logger: Arc<crate::logger::Logger>,
	) -> Self {
		Self {
			handler,
			pending: Mutex::new(Vec::new()),
			connected: Mutex::new(HashMap::new()),
			logger,
		}
	}

	/// Calls the handler, if any. A panic is caught and logged: it must not poison LDK's peer locks
	/// that the call runs under, which would stop every later `process_events`.
	fn call(&self, what: &str, f: impl FnOnce(&dyn AppMessageHandler)) {
		if let Some(handler) = &self.handler {
			if catch_unwind(AssertUnwindSafe(|| f(handler.as_ref()))).is_err() {
				log_error!(self.logger, "The app message handler panicked in {}; dropped", what);
			}
		}
	}

	/// Reads an app message's payload. `None` (the message is ignored, as LDK ignores any unknown
	/// odd type, and the peer stays connected) without a handler, or for a payload that isn't
	/// UTF-8 or has a zero byte. Its length needs no check: the frame's is a `u16`, so at most
	/// [`MAX_APP_MESSAGE_LEN`] after the type.
	fn read<RD: LengthLimitedRead>(&self, buffer: &mut RD) -> Option<AppMessage> {
		self.handler.as_ref()?;
		let mut bytes = vec![0u8; buffer.remaining_bytes() as usize];
		if buffer.read_exact(&mut bytes).is_err() || bytes.contains(&0) {
			log_debug!(self.logger, "Dropped an unreadable app message or one with a zero byte");
			return None;
		}
		match String::from_utf8(bytes) {
			Ok(payload) => Some(AppMessage { payload }),
			Err(_) => {
				log_debug!(self.logger, "Dropped an app message that isn't UTF-8");
				None
			},
		}
	}

	/// Queues `payload` for `peer`, which must be connected. The caller then has the
	/// `PeerManager` process its events. `Ok` means queued, not delivered: a disconnect first drops
	/// it.
	pub(crate) fn send(&self, peer: PublicKey, payload: String) -> Result<(), Error> {
		if payload.len() > MAX_APP_MESSAGE_LEN || payload.as_bytes().contains(&0) {
			return Err(Error::InvalidAppMessage);
		}
		if !self.connected.lock().expect("lock").contains_key(&peer) {
			return Err(Error::ConnectionFailed);
		}
		self.pending.lock().expect("lock").push((peer, AppMessage { payload }));
		Ok(())
	}

	/// Whether `peer` is connected and its `Init` set [`APP_MESSAGES_FEATURE_BIT`] or its even
	/// twin.
	pub(crate) fn peer_supports(&self, peer: &PublicKey) -> bool {
		self.connected.lock().expect("lock").get(peer).copied().unwrap_or(false)
	}

	fn add_init_feature(&self, features: &mut InitFeatures) {
		if self.handler.is_some() {
			features
				.set_optional_custom_bit(APP_MESSAGES_FEATURE_BIT)
				.expect("APP_MESSAGES_FEATURE_BIT is in the custom range");
		}
	}

	/// A message from `peer`, to the handler. Dropped when `peer` didn't announce app messages:
	/// our apps always do, so anything else is not one of ours.
	fn received(&self, peer: PublicKey, msg: AppMessage) {
		if !self.peer_supports(&peer) {
			log_debug!(
				self.logger,
				"Dropped an app message from {}, which didn't announce them",
				peer
			);
			return;
		}
		self.call("received", |handler| handler.received(peer, msg.payload));
	}

	fn peer_connected(&self, peer: PublicKey, features: &InitFeatures) {
		let supports = sets_app_messages_bit(features);
		self.connected.lock().expect("lock").insert(peer, supports);
		self.call("connected", |handler| handler.connected(peer, supports));
	}

	/// Forgets `peer`, and drops what is still queued for it, so nothing reaches its next
	/// connection.
	fn peer_disconnected(&self, peer: PublicKey) {
		self.pending.lock().expect("lock").retain(|(to, _)| *to != peer);
		let was_connected = self.connected.lock().expect("lock").remove(&peer).is_some();
		if was_connected {
			self.call("disconnected", |handler| handler.disconnected(peer));
		}
	}

	fn take_pending(&self) -> Vec<(PublicKey, AppMessage)> {
		std::mem::take(&mut *self.pending.lock().expect("lock"))
	}

	/// `CustomMessageReader::read`: our type to the app messages, every other to `lsps`.
	fn read_beside<LM, RD>(
		&self, lsps: &LM, message_type: u16, buffer: &mut RD,
	) -> Result<Option<NodeCustomMessage>, DecodeError>
	where
		LM: CustomMessageReader<CustomMessage = RawLSPSMessage>,
		RD: LengthLimitedRead,
	{
		if message_type == APP_MESSAGE_TYPE {
			return Ok(self.read(buffer).map(NodeCustomMessage::App));
		}
		Ok(lsps.read(message_type, buffer)?.map(NodeCustomMessage::Lsps))
	}

	/// `CustomMessageHandler::handle_custom_message`. An app message is never an error, so it never
	/// costs the peer its connection.
	fn handle_beside<LM: CustomMessageHandler<CustomMessage = RawLSPSMessage>>(
		&self, lsps: &LM, msg: NodeCustomMessage, sender: PublicKey,
	) -> Result<(), LightningError> {
		match msg {
			NodeCustomMessage::Lsps(msg) => lsps.handle_custom_message(msg, sender),
			NodeCustomMessage::App(msg) => {
				self.received(sender, msg);
				Ok(())
			},
		}
	}

	/// `get_and_clear_pending_msg`: LSPS's first, then ours, each in its own order.
	fn pending_beside<LM: CustomMessageHandler<CustomMessage = RawLSPSMessage>>(
		&self, lsps: &LM,
	) -> Vec<(PublicKey, NodeCustomMessage)> {
		let lsps = lsps.get_and_clear_pending_msg().into_iter();
		let lsps = lsps.map(|(peer, msg)| (peer, NodeCustomMessage::Lsps(msg)));
		let app = self.take_pending().into_iter();
		lsps.chain(app.map(|(peer, msg)| (peer, NodeCustomMessage::App(msg)))).collect()
	}

	/// `provided_init_features`: LSPS's, plus our bit when we take app messages.
	fn init_features_beside<LM: CustomMessageHandler<CustomMessage = RawLSPSMessage>>(
		&self, lsps: &LM, their_node_id: PublicKey,
	) -> InitFeatures {
		let mut features = lsps.provided_init_features(their_node_id);
		self.add_init_feature(&mut features);
		features
	}

	/// `peer_connected`: LSPS first; app messages only once it accepted the peer, so the handler
	/// is never told of a connection LDK then refuses.
	fn connected_beside<LM: CustomMessageHandler<CustomMessage = RawLSPSMessage>>(
		&self, lsps: &LM, their_node_id: PublicKey, msg: &Init, inbound: bool,
	) -> Result<(), ()> {
		lsps.peer_connected(their_node_id, msg, inbound)?;
		self.peer_connected(their_node_id, &msg.features);
		Ok(())
	}

	fn disconnected_beside<LM: CustomMessageHandler<CustomMessage = RawLSPSMessage>>(
		&self, lsps: &LM, their_node_id: PublicKey,
	) {
		self.peer_disconnected(their_node_id);
		lsps.peer_disconnected(their_node_id)
	}
}

pub(crate) struct NodeCustomMessageHandler<L: Deref>
where
	L::Target: Logger,
{
	liquidity_source: Arc<LiquiditySource<L>>,
	/// Blocknil patch: told when a peer connects, to release what is held for it.
	held_payments: Arc<HeldPayments>,
	/// Blocknil patch: app messages, beside LSPS (see [`AppMessageHandler`]).
	app_messages: Arc<AppMessages>,
}

impl<L: Deref> NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	pub(crate) fn new(
		liquidity_source: Arc<LiquiditySource<L>>, held_payments: Arc<HeldPayments>,
		app_messages: Arc<AppMessages>,
	) -> Self {
		Self { liquidity_source, held_payments, app_messages }
	}
}

impl<L: Deref> CustomMessageReader for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	type CustomMessage = NodeCustomMessage;

	fn read<RD: LengthLimitedRead>(
		&self, message_type: u16, buffer: &mut RD,
	) -> Result<Option<Self::CustomMessage>, DecodeError> {
		// Blocknil patch: app messages beside LSPS (see `AppMessages::read_beside`).
		let lsps = self.liquidity_source.liquidity_manager();
		self.app_messages.read_beside(&*lsps, message_type, buffer)
	}
}

impl<L: Deref> CustomMessageHandler for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	fn handle_custom_message(
		&self, msg: Self::CustomMessage, sender_node_id: PublicKey,
	) -> Result<(), LightningError> {
		let lsps = self.liquidity_source.liquidity_manager();
		self.app_messages.handle_beside(&*lsps, msg, sender_node_id)
	}

	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
		self.app_messages.pending_beside(&*self.liquidity_source.liquidity_manager())
	}

	fn provided_node_features(&self) -> NodeFeatures {
		self.liquidity_source.liquidity_manager().provided_node_features()
	}

	fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
		let lsps = self.liquidity_source.liquidity_manager();
		self.app_messages.init_features_beside(&*lsps, their_node_id)
	}

	fn peer_connected(
		&self, their_node_id: PublicKey, msg: &Init, inbound: bool,
	) -> Result<(), ()> {
		// Blocknil patch: a client is back; what is held for it goes out once its channel is
		// reestablished. Every node runs this handler, whatever its async payments role.
		self.held_payments.peer_connected(their_node_id);
		let lsps = self.liquidity_source.liquidity_manager();
		self.app_messages.connected_beside(&*lsps, their_node_id, msg, inbound)
	}

	fn peer_disconnected(&self, their_node_id: PublicKey) {
		// Blocknil patch (ldk3-lost-forward-match): ends the connection `held_payments` matches
		// a lost forward against.
		self.held_payments.peer_disconnected(&their_node_id);
		let lsps = self.liquidity_source.liquidity_manager();
		self.app_messages.disconnected_beside(&*lsps, their_node_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning_liquidity::lsps0::ser::LSPS_MESSAGE_TYPE_ID;

	#[derive(Debug, PartialEq)]
	enum Seen {
		Received(PublicKey, String),
		Connected(PublicKey, bool),
		Disconnected(PublicKey),
	}

	#[derive(Default)]
	struct Recorder(Mutex<Vec<Seen>>);

	impl AppMessageHandler for Recorder {
		fn received(&self, peer: PublicKey, payload: String) {
			self.0.lock().unwrap().push(Seen::Received(peer, payload));
		}
		fn connected(&self, peer: PublicKey, supports_app_messages: bool) {
			self.0.lock().unwrap().push(Seen::Connected(peer, supports_app_messages));
		}
		fn disconnected(&self, peer: PublicKey) {
			self.0.lock().unwrap().push(Seen::Disconnected(peer));
		}
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

	/// Stands in for the `LiquidityManager`: reads 37913 only, records what reaches it, sets the
	/// LSPS bit (729), queues what the test gives it, and can refuse a peer.
	#[derive(Default)]
	struct FakeLsps {
		handled: Mutex<Vec<(PublicKey, String)>>,
		pending: Mutex<Vec<(PublicKey, RawLSPSMessage)>>,
		connected: Mutex<Vec<PublicKey>>,
		disconnected: Mutex<Vec<PublicKey>>,
		refuse: bool,
	}

	impl CustomMessageReader for FakeLsps {
		type CustomMessage = RawLSPSMessage;
		fn read<RD: LengthLimitedRead>(
			&self, message_type: u16, buffer: &mut RD,
		) -> Result<Option<RawLSPSMessage>, DecodeError> {
			if message_type != LSPS_MESSAGE_TYPE_ID {
				return Ok(None);
			}
			let mut bytes = vec![0u8; buffer.remaining_bytes() as usize];
			buffer.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
			let payload = String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?;
			Ok(Some(RawLSPSMessage { payload }))
		}
	}

	impl CustomMessageHandler for FakeLsps {
		fn handle_custom_message(
			&self, msg: RawLSPSMessage, sender: PublicKey,
		) -> Result<(), LightningError> {
			self.handled.lock().unwrap().push((sender, msg.payload));
			Ok(())
		}
		fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, RawLSPSMessage)> {
			std::mem::take(&mut *self.pending.lock().unwrap())
		}
		fn peer_disconnected(&self, peer: PublicKey) {
			self.disconnected.lock().unwrap().push(peer);
		}
		fn peer_connected(&self, peer: PublicKey, _: &Init, _: bool) -> Result<(), ()> {
			self.connected.lock().unwrap().push(peer);
			if self.refuse {
				Err(())
			} else {
				Ok(())
			}
		}
		fn provided_node_features(&self) -> NodeFeatures {
			NodeFeatures::empty()
		}
		fn provided_init_features(&self, _: PublicKey) -> InitFeatures {
			let mut features = InitFeatures::empty();
			features.set_optional_custom_bit(729).unwrap();
			features
		}
	}

	fn peer(byte: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
	}

	fn logger() -> Arc<crate::logger::Logger> {
		Arc::new(crate::logger::Logger::new_log_facade())
	}

	fn with_handler() -> (Arc<Recorder>, AppMessages) {
		let recorder = Arc::new(Recorder::default());
		let handler: Arc<dyn AppMessageHandler> = recorder.clone();
		(recorder, AppMessages::new(Some(handler), logger()))
	}

	fn without_handler() -> AppMessages {
		AppMessages::new(None, logger())
	}

	fn with_bit(bit: usize) -> InitFeatures {
		let mut features = InitFeatures::empty();
		if bit % 2 == 0 {
			features.set_required_custom_bit(bit).unwrap();
		} else {
			features.set_optional_custom_bit(bit).unwrap();
		}
		features
	}

	fn init(features: InitFeatures) -> Init {
		Init { features, networks: None, remote_network_address: None }
	}

	fn has_bit(features: &InitFeatures, bit: usize) -> bool {
		features.le_flags().get(bit / 8).map_or(false, |b| b & (1 << (bit % 8)) != 0)
	}

	#[test]
	fn type_and_bit_are_odd_and_custom() {
		assert_eq!(APP_MESSAGE_TYPE % 2, 1);
		assert!(APP_MESSAGE_TYPE >= 32768);
		assert_ne!(APP_MESSAGE_TYPE, LSPS_MESSAGE_TYPE_ID);
		assert_eq!(APP_MESSAGES_FEATURE_BIT % 2, 1);
		assert!(APP_MESSAGES_FEATURE_BIT >= 256);
	}

	#[test]
	fn our_type_is_read_and_reaches_the_handler() {
		let (recorder, app) = with_handler();
		app.peer_connected(peer(1), &with_bit(APP_MESSAGES_FEATURE_BIT));
		let payload = r#"{"jsonrpc":"2.0","method":"blocknil.get_quotes","params":{},"id":"1"}"#;
		let msg = app.read(&mut payload.as_bytes()).expect("read");
		assert_eq!(msg.payload, payload);
		app.received(peer(1), msg);
		assert_eq!(
			*recorder.0.lock().unwrap(),
			vec![Seen::Connected(peer(1), true), Seen::Received(peer(1), payload.into())]
		);
	}

	#[test]
	fn written_as_the_bare_payload_under_our_type() {
		let app = NodeCustomMessage::App(AppMessage { payload: "héllo".into() });
		assert_eq!(app.type_id(), APP_MESSAGE_TYPE);
		assert_eq!(app.encode(), "héllo".as_bytes());
		let lsps = NodeCustomMessage::Lsps(RawLSPSMessage { payload: "{}".into() });
		assert_eq!(lsps.type_id(), LSPS_MESSAGE_TYPE_ID);
		assert_eq!(lsps.encode(), b"{}");
	}

	#[test]
	fn a_zero_byte_or_not_utf8_is_dropped_on_read() {
		let (_, app) = with_handler();
		let longest = vec![b'a'; MAX_APP_MESSAGE_LEN];
		assert!(app.read(&mut &longest[..]).is_some());
		assert_eq!(app.read(&mut &b""[..]), Some(AppMessage { payload: String::new() }));
		assert!(app.read(&mut &b"a\0b"[..]).is_none());
		assert!(app.read(&mut &[0xff, 0xfe][..]).is_none());
	}

	#[test]
	fn without_a_handler_our_type_is_ignored_and_the_bit_is_not_set() {
		let app = without_handler();
		assert!(app.read(&mut &b"{}"[..]).is_none());
		let mut features = InitFeatures::empty();
		app.add_init_feature(&mut features);
		assert!(!has_bit(&features, APP_MESSAGES_FEATURE_BIT));

		let (_, app) = with_handler();
		app.add_init_feature(&mut features);
		assert!(has_bit(&features, APP_MESSAGES_FEATURE_BIT));
	}

	#[test]
	fn connect_records_either_bit_of_the_pair_and_disconnect_forgets_it() {
		let (recorder, app) = with_handler();
		app.peer_connected(peer(1), &with_bit(APP_MESSAGES_FEATURE_BIT));
		app.peer_connected(peer(2), &InitFeatures::empty());
		app.peer_connected(peer(4), &with_bit(APP_MESSAGES_FEATURE_BIT - 1));
		app.peer_connected(peer(5), &with_bit(APP_MESSAGES_FEATURE_BIT + 2));
		assert!(app.peer_supports(&peer(1)));
		assert!(!app.peer_supports(&peer(2)));
		assert!(!app.peer_supports(&peer(3)));
		assert!(app.peer_supports(&peer(4)), "the required twin, 412, counts too");
		assert!(!app.peer_supports(&peer(5)));

		app.peer_disconnected(peer(1));
		app.peer_disconnected(peer(3));
		assert!(!app.peer_supports(&peer(1)));
		assert_eq!(
			*recorder.0.lock().unwrap(),
			vec![
				Seen::Connected(peer(1), true),
				Seen::Connected(peer(2), false),
				Seen::Connected(peer(4), true),
				Seen::Connected(peer(5), false),
				Seen::Disconnected(peer(1)),
			]
		);
	}

	#[test]
	fn a_message_from_a_peer_that_didnt_announce_the_bit_is_dropped() {
		let (recorder, app) = with_handler();
		app.peer_connected(peer(2), &InitFeatures::empty());
		app.received(peer(2), AppMessage { payload: "{}".into() });
		app.received(peer(3), AppMessage { payload: "{}".into() });
		assert_eq!(*recorder.0.lock().unwrap(), vec![Seen::Connected(peer(2), false)]);
	}

	#[test]
	fn send_queues_for_a_connected_peer_only() {
		let (_, app) = with_handler();
		assert_eq!(app.send(peer(1), "{}".into()), Err(Error::ConnectionFailed));

		app.peer_connected(peer(1), &InitFeatures::empty());
		let too_long = "a".repeat(MAX_APP_MESSAGE_LEN + 1);
		assert_eq!(app.send(peer(1), too_long), Err(Error::InvalidAppMessage));
		assert_eq!(app.send(peer(1), "a\0".into()), Err(Error::InvalidAppMessage));
		assert!(app.take_pending().is_empty());

		app.send(peer(1), "a".repeat(MAX_APP_MESSAGE_LEN)).unwrap();
		app.send(peer(1), "{}".into()).unwrap();
		let pending = app.take_pending();
		assert_eq!(pending.len(), 2);
		assert_eq!(pending[1], (peer(1), AppMessage { payload: "{}".into() }));
		assert!(app.take_pending().is_empty());

		app.peer_disconnected(peer(1));
		assert_eq!(app.send(peer(1), "{}".into()), Err(Error::ConnectionFailed));
	}

	#[test]
	fn a_disconnect_drops_what_is_queued_for_that_peer_only() {
		let (_, app) = with_handler();
		app.peer_connected(peer(1), &InitFeatures::empty());
		app.peer_connected(peer(2), &InitFeatures::empty());
		app.send(peer(1), "for the old connection".into()).unwrap();
		app.send(peer(2), "kept".into()).unwrap();
		app.peer_disconnected(peer(1));
		app.peer_connected(peer(1), &InitFeatures::empty());
		assert_eq!(app.take_pending(), vec![(peer(2), AppMessage { payload: "kept".into() })]);
	}

	#[test]
	fn a_panicking_handler_is_caught_and_the_state_stays_usable() {
		let handler: Arc<dyn AppMessageHandler> = Arc::new(Panicker);
		let app = AppMessages::new(Some(handler), logger());
		app.peer_connected(peer(1), &with_bit(APP_MESSAGES_FEATURE_BIT));
		assert!(app.peer_supports(&peer(1)));
		app.received(peer(1), AppMessage { payload: "{}".into() });
		app.send(peer(1), "{}".into()).unwrap();
		assert_eq!(app.take_pending().len(), 1);
		app.peer_disconnected(peer(1));
		assert!(!app.peer_supports(&peer(1)));
		app.peer_connected(peer(1), &InitFeatures::empty());
		assert!(app.send(peer(1), "{}".into()).is_ok());
	}

	#[test]
	fn read_dispatch_sends_37913_to_lsps_ours_to_the_app_and_others_nowhere() {
		let lsps = FakeLsps::default();
		let (_, app) = with_handler();
		let read = |ty, bytes: &[u8]| app.read_beside(&lsps, ty, &mut &bytes[..]).unwrap();
		assert!(
			matches!(read(LSPS_MESSAGE_TYPE_ID, b"{}"), Some(NodeCustomMessage::Lsps(m)) if m.payload == "{}")
		);
		assert!(
			matches!(read(APP_MESSAGE_TYPE, b"hi"), Some(NodeCustomMessage::App(m)) if m.payload == "hi")
		);
		assert!(read(APP_MESSAGE_TYPE, b"a\0").is_none());
		assert!(read(40215, b"{}").is_none());
		// Without an app handler, our type is still not LSPS's: nothing reads it.
		let app = without_handler();
		assert!(app.read_beside(&lsps, APP_MESSAGE_TYPE, &mut &b"{}"[..]).unwrap().is_none());
	}

	#[test]
	fn handle_dispatch_sends_lsps_to_lsps_and_ours_to_the_handler() {
		let lsps = FakeLsps::default();
		let (recorder, app) = with_handler();
		app.connected_beside(&lsps, peer(1), &init(with_bit(APP_MESSAGES_FEATURE_BIT)), true)
			.unwrap();
		let lsps_msg = NodeCustomMessage::Lsps(RawLSPSMessage { payload: "lsps".into() });
		app.handle_beside(&lsps, lsps_msg, peer(1)).unwrap();
		let app_msg = NodeCustomMessage::App(AppMessage { payload: "app".into() });
		app.handle_beside(&lsps, app_msg, peer(1)).unwrap();
		assert_eq!(*lsps.handled.lock().unwrap(), vec![(peer(1), "lsps".to_string())]);
		assert_eq!(
			*recorder.0.lock().unwrap(),
			vec![Seen::Connected(peer(1), true), Seen::Received(peer(1), "app".into())]
		);
	}

	#[test]
	fn init_features_are_lsps_ones_plus_our_bit() {
		let lsps = FakeLsps::default();
		let (_, app) = with_handler();
		let features = app.init_features_beside(&lsps, peer(1));
		assert!(has_bit(&features, 729) && has_bit(&features, APP_MESSAGES_FEATURE_BIT));
		let features = without_handler().init_features_beside(&lsps, peer(1));
		assert!(has_bit(&features, 729) && !has_bit(&features, APP_MESSAGES_FEATURE_BIT));
	}

	#[test]
	fn pending_drains_lsps_first_then_ours_in_order() {
		let lsps = FakeLsps::default();
		lsps.pending.lock().unwrap().push((peer(2), RawLSPSMessage { payload: "l1".into() }));
		let (_, app) = with_handler();
		app.connected_beside(&lsps, peer(1), &init(InitFeatures::empty()), true).unwrap();
		app.send(peer(1), "a1".into()).unwrap();
		app.send(peer(1), "a2".into()).unwrap();
		let drained: Vec<_> = app
			.pending_beside(&lsps)
			.into_iter()
			.map(|(to, msg)| match msg {
				NodeCustomMessage::Lsps(m) => (to, format!("lsps:{}", m.payload)),
				NodeCustomMessage::App(m) => (to, format!("app:{}", m.payload)),
			})
			.collect();
		assert_eq!(
			drained,
			vec![
				(peer(2), "lsps:l1".to_string()),
				(peer(1), "app:a1".to_string()),
				(peer(1), "app:a2".to_string()),
			]
		);
		assert!(app.pending_beside(&lsps).is_empty());
	}

	#[test]
	fn connect_tells_lsps_first_and_the_app_only_if_lsps_accepts() {
		let refusing = FakeLsps { refuse: true, ..Default::default() };
		let (recorder, app) = with_handler();
		let bit = init(with_bit(APP_MESSAGES_FEATURE_BIT));
		assert!(app.connected_beside(&refusing, peer(1), &bit, true).is_err());
		assert!(!app.peer_supports(&peer(1)));
		assert!(recorder.0.lock().unwrap().is_empty());

		let lsps = FakeLsps::default();
		app.connected_beside(&lsps, peer(1), &bit, true).unwrap();
		app.disconnected_beside(&lsps, peer(1));
		assert_eq!(*lsps.connected.lock().unwrap(), vec![peer(1)]);
		assert_eq!(*lsps.disconnected.lock().unwrap(), vec![peer(1)]);
		assert_eq!(
			*recorder.0.lock().unwrap(),
			vec![Seen::Connected(peer(1), true), Seen::Disconnected(peer(1))]
		);
	}
}
