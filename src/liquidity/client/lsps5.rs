// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: the LSPS5 (webhook) client, which upstream ldk-node leaves off.
//!
//! A wallet registers the URL its push relay gives it with its LSP, so the LSP can wake the phone
//! when a payment waits for it.

use std::ops::Deref;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use lightning_liquidity::lsps5::event::LSPS5ClientEvent;

use crate::logger::{log_debug, log_error, log_info, LdkLogger};
use crate::types::LiquidityManager;
use crate::Error;

pub(crate) struct LSPS5ClientLiquiditySource<L: Deref>
where
	L::Target: LdkLogger,
{
	pub(crate) liquidity_manager: Arc<LiquidityManager>,
	pub(crate) logger: L,
}

impl<L: Deref> LSPS5ClientLiquiditySource<L>
where
	L::Target: LdkLogger,
{
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

	/// Logs the provider's answer.
	pub(crate) fn handle_event(&self, event: LSPS5ClientEvent) {
		match event {
			LSPS5ClientEvent::WebhookRegistered {
				counterparty_node_id,
				app_name,
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
			},
			LSPS5ClientEvent::WebhookRegistrationFailed {
				counterparty_node_id,
				app_name,
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
			},
			other => log_debug!(self.logger, "LSPS5 client event: {:?}", other),
		}
	}
}
