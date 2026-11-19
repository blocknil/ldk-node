// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::sync::Arc;

use bitcoin_payment_instructions::amount::Amount as BPIAmount;
use bitcoin_payment_instructions::dns_resolver::DNSHrnResolver;
use bitcoin_payment_instructions::hrn_resolution::{
	HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};
use bitcoin_payment_instructions::onion_message_resolver::LDKOnionMessageDNSSECHrnResolver;

use crate::logger::Logger;
use crate::types::Graph;

#[derive(Clone)]
pub enum HRNResolver {
	Onion(Arc<LDKOnionMessageDNSSECHrnResolver<Arc<Graph>, Arc<Logger>>>),
	Local(Arc<DNSHrnResolver>),
}

impl HrnResolver for HRNResolver {
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		match self {
			HRNResolver::Onion(inner) => inner.resolve_hrn(hrn),
			HRNResolver::Local(inner) => inner.resolve_hrn(hrn),
		}
	}

	fn resolve_lnurl<'a>(&'a self, url: &'a str) -> HrnResolutionFuture<'a> {
		match self {
			HRNResolver::Onion(inner) => inner.resolve_lnurl(url),
			HRNResolver::Local(inner) => inner.resolve_lnurl(url),
		}
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, callback_url: String, amount: BPIAmount, expected_description_hash: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		match self {
			HRNResolver::Onion(inner) => {
				inner.resolve_lnurl_to_invoice(callback_url, amount, expected_description_hash)
			},
			HRNResolver::Local(inner) => {
				inner.resolve_lnurl_to_invoice(callback_url, amount, expected_description_hash)
			},
		}
	}
}

/// Blocknil patch: why [`crate::Node::resolve_name`] could not resolve a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameResolutionError {
	/// The node isn't running, so no query can be sent.
	NotRunning,
	/// No answer came within the resolution timeout (5 seconds). Onion messages are best-effort:
	/// the resolver may be offline or its DNS slow.
	TimedOut,
	/// The lookup failed, with the resolver's reason: not a name, no DNSSEC record, a proof that
	/// didn't validate, no resolver to ask.
	Failed(String),
}

impl std::fmt::Display for NameResolutionError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::NotRunning => write!(f, "The node is not running."),
			Self::TimedOut => write!(f, "Looking the name up timed out."),
			Self::Failed(reason) => write!(f, "{}", reason),
		}
	}
}

impl std::error::Error for NameResolutionError {}
