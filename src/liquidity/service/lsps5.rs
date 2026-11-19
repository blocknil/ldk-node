// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: the LSPS5 (webhook) service, which upstream ldk-node leaves off.
//!
//! A client registers a webhook URL with us; when a payment or an onion message waits for it, we
//! ask LDK to notify that URL, and LDK hands the signed notification to the sender the
//! application registered ([`crate::Node::set_webhook_sender`]), which POSTs it. That is how a
//! phone whose app is closed is woken. Which hosts we POST to is the sender's business: our
//! provider's sender only posts to its own push relay.

use std::ops::Deref;
use std::sync::{Arc, RwLock};

use bitcoin::secp256k1::PublicKey;
use lightning_liquidity::lsps5::event::LSPS5ServiceEvent;

use crate::logger::{log_debug, log_error, LdkLogger};
use crate::types::LiquidityManager;

/// Represents the configuration of the LSPS5 (webhook) service.
///
/// See [bLIP-55 / LSPS5] for more information. Blocknil patch.
///
/// [bLIP-55 / LSPS5]: https://github.com/lightning/blips/blob/master/blip-0055.md
#[derive(Debug, Clone)]
pub struct LSPS5ServiceConfig {
	/// How many webhook URLs one client may register with us.
	pub max_webhooks_per_client: u32,
}

impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self { max_webhooks_per_client: 10 }
	}
}

/// A webhook notification to deliver: a JSON body this node signed, and where to POST it.
///
/// Blocknil patch (LSPS5). Delivered to the sender registered with
/// [`crate::Node::set_webhook_sender`], which runs on a thread of its own: a sender may block for
/// as long as its own timeout, and the notification is dropped if it fails (the payment it
/// announces stops waiting for the phone after the hold).
#[derive(Clone, Debug)]
pub struct WebhookPost {
	/// The URL the client registered.
	pub url: String,
	/// The headers to send with the POST, including the LSPS5 timestamp and signature.
	pub headers: Vec<(String, String)>,
	/// The JSON body, exactly as signed: `serde_json::to_string` of the notification.
	pub body: String,
}

/// Delivers a [`WebhookPost`]; see [`crate::Node::set_webhook_sender`]. Blocknil patch (LSPS5).
pub type OnWebhook = Arc<dyn Fn(WebhookPost) + Send + Sync>;

pub(crate) struct LSPS5ServiceLiquiditySource<L: Deref>
where
	L::Target: LdkLogger,
{
	pub(crate) webhook_sender: RwLock<Option<OnWebhook>>,
	pub(crate) liquidity_manager: Arc<LiquidityManager>,
	pub(crate) logger: L,
}

impl<L: Deref> LSPS5ServiceLiquiditySource<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn set_webhook_sender(&self, sender: OnWebhook) {
		*self.webhook_sender.write().expect("lock") = Some(sender);
	}

	/// Tells `client`'s registered webhooks that a payment is waiting for it. `false` when LDK
	/// refused (no LSPS5 service, or one was sent less than the cooldown ago); a client without a
	/// webhook gets nothing, and that is `true`.
	pub(crate) fn notify_payment_incoming(&self, client: PublicKey) -> bool {
		match self.liquidity_manager.lsps5_service_handler() {
			Some(handler) => match handler.notify_payment_incoming(client) {
				Ok(()) => true,
				Err(e) => {
					log_debug!(self.logger, "Webhook for {} not sent: {:?}", client, e);
					false
				},
			},
			None => false,
		}
	}

	/// Tells `client`'s registered webhooks that an onion message (a BOLT12 invoice request,
	/// typically) is waiting for it. As [`Self::notify_payment_incoming`].
	pub(crate) fn notify_onion_message_incoming(&self, client: PublicKey) -> bool {
		match self.liquidity_manager.lsps5_service_handler() {
			Some(handler) => match handler.notify_onion_message_incoming(client) {
				Ok(()) => true,
				Err(e) => {
					log_debug!(
						self.logger,
						"Onion message webhook for {} not sent: {:?}",
						client,
						e
					);
					false
				},
			},
			None => false,
		}
	}

	pub(crate) fn is_enabled(&self) -> bool {
		self.liquidity_manager.lsps5_service_handler().is_some()
	}

	/// Hands a notification to the sender, on a thread of its own: a POST that hangs must not hold
	/// up the node, and there is no point retrying past the hold, so a failure drops it.
	pub(crate) fn handle_event(&self, event: LSPS5ServiceEvent) {
		match event {
			LSPS5ServiceEvent::SendWebhookNotification {
				counterparty_node_id,
				url,
				notification,
				headers,
				..
			} => {
				let body = match serde_json::to_string(&notification) {
					Ok(body) => body,
					Err(e) => {
						log_error!(self.logger, "Webhook notification doesn't serialize: {:?}", e);
						return;
					},
				};
				let post = WebhookPost { url: url.to_string(), headers, body };
				let sender = self.webhook_sender.read().expect("lock").clone();
				match sender {
					Some(sender) => {
						log_debug!(
							self.logger,
							"Sending webhook {:?} to {} for {}",
							post.url,
							counterparty_node_id,
							post.body
						);
						let spawned = std::thread::Builder::new()
							.name("lsps5-webhook".to_string())
							.spawn(move || sender(post));
						if let Err(e) = spawned {
							log_error!(self.logger, "Couldn't start the webhook sender: {}", e);
						}
					},
					None => log_error!(
						self.logger,
						"No webhook sender registered; dropping the notification for {}",
						counterparty_node_id
					),
				}
			},
		}
	}
}
