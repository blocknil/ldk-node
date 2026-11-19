// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: the LSPS5 (webhook) client, which upstream ldk-node leaves off.
//!
//! A wallet registers the URL its push relay gives it with its LSP, so the LSP can wake the phone
//! when a payment waits for it. The LSP's answers reach the wallet through
//! [`crate::Node::set_webhook_result_handler`].

use std::ops::Deref;
use std::sync::{Arc, RwLock};

use bitcoin::secp256k1::PublicKey;
use lightning_liquidity::lsps5::event::LSPS5ClientEvent;

use crate::logger::{log_debug, log_error, log_info, LdkLogger};
use crate::types::LiquidityManager;
use crate::Error;

/// The provider's answer to a webhook registration, as the LSPS5 client reports it.
///
/// Blocknil patch (LSPS5): the wallet shows "Notifications: on/off" from this, so the answer has to
/// be readable rather than only logged. Delivered to the handler set with
/// [`crate::Node::set_webhook_result_handler`], on the node's event handling: it must not block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookResult {
	/// The URL that was registered, as the provider echoes it back.
	pub url: String,
	/// The app name it was registered under.
	pub app_name: String,
	/// True when the provider accepted it; false when it refused (see `error`).
	pub accepted: bool,
	/// True when the provider already had this exact URL and changed nothing.
	pub no_change: bool,
	/// Why it was refused, when it was. Empty otherwise.
	pub error: String,
}

/// Receives a [`WebhookResult`]; see [`crate::Node::set_webhook_result_handler`]. Blocknil patch.
pub type OnWebhookResult = Arc<dyn Fn(WebhookResult) + Send + Sync>;

pub(crate) struct LSPS5ClientLiquiditySource<L: Deref>
where
	L::Target: LdkLogger,
{
	pub(crate) result_handler: RwLock<Option<OnWebhookResult>>,
	pub(crate) liquidity_manager: Arc<LiquidityManager>,
	pub(crate) logger: L,
}

impl<L: Deref> LSPS5ClientLiquiditySource<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn set_result_handler(&self, handler: OnWebhookResult) {
		*self.result_handler.write().expect("lock") = Some(handler);
	}

	fn report(&self, result: WebhookResult) {
		let handler = self.result_handler.read().expect("lock").clone();
		if let Some(handler) = handler {
			handler(result);
		}
	}

	/// Registers `url` as `app_name`'s webhook with `lsp`. The answer comes later, as an event.
	pub(crate) fn set_webhook(
		&self, lsp: PublicKey, app_name: String, url: String,
	) -> Result<(), Error> {
		let handler = self
			.liquidity_manager
			.lsps5_client_handler()
			.ok_or(Error::WebhookRegistrationFailed)?;
		handler.set_webhook(lsp, app_name, url).map(|_| ()).map_err(|e| {
			log_error!(self.logger, "Registering the webhook was refused: {:?}", e);
			Error::WebhookRegistrationFailed
		})
	}

	/// Logs the provider's answer and hands it to the wallet.
	pub(crate) fn handle_event(&self, event: LSPS5ClientEvent) {
		match event {
			LSPS5ClientEvent::WebhookRegistered {
				counterparty_node_id,
				app_name,
				url,
				no_change,
				..
			} => {
				log_info!(
					self.logger,
					"Webhook {:?} registered with {} (unchanged: {})",
					app_name,
					counterparty_node_id,
					no_change
				);
				self.report(WebhookResult {
					url: url.to_string(),
					app_name: app_name.to_string(),
					accepted: true,
					no_change,
					error: String::new(),
				});
			},
			LSPS5ClientEvent::WebhookRegistrationFailed {
				counterparty_node_id,
				app_name,
				url,
				error,
				..
			} => {
				log_error!(
					self.logger,
					"Webhook {:?} refused by {}: {:?}",
					app_name,
					counterparty_node_id,
					error
				);
				self.report(WebhookResult {
					url: url.to_string(),
					app_name: app_name.to_string(),
					accepted: false,
					no_change: false,
					error: format!("{error:?}"),
				});
			},
			other => log_debug!(self.logger, "LSPS5 client event: {:?}", other),
		}
	}
}
