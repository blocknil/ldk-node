// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: resolving BIP 353 human-readable names (`user@domain`) through the node's
//! onion messenger.
//!
//! The wallet owns the lookup: it sends the bLIP-32 query to its own provider as an onion message
//! and validates the DNSSEC proof that comes back itself, which is why ldk-node only needs a
//! handle to start the lookup and a place to return the answer. The handler that carries the
//! messages is the same object (see [`crate::Builder::set_name_resolver`]).

use std::fmt;
use std::sync::Arc;

use core::future::Future;
use core::pin::Pin;

use lightning::onion_message::dns_resolution::DNSResolverMessageHandler;

/// How long [`crate::Node::resolve_name`] waits for an answer before it gives up.
pub const NAME_RESOLUTION_TIMEOUT_SECS: u64 = 10;

/// A resolver for BIP 353 names, as the wallet implements it.
///
/// [`crate::Node::resolve_name`] awaits the future with [`NAME_RESOLUTION_TIMEOUT_SECS`], so an
/// implementation does not need its own timeout.
pub trait NameResolver: Send + Sync {
	/// Resolves `name` (`user@domain`, without the leading `₿`) to the payment instructions in its
	/// DNSSEC record: a BIP 321 URI for the caller to parse, or the reason it can't be had.
	fn resolve_name<'a>(
		&'a self, name: &'a str,
	) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

/// Why a BIP 353 name could not be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameResolutionError {
	/// No [`NameResolver`] was configured on the [`crate::Node`].
	NotConfigured,
	/// The resolver did not answer within [`NAME_RESOLUTION_TIMEOUT_SECS`]. Onion messages are
	/// best-effort: the provider may be offline, or its DNS may be slow.
	TimedOut,
	/// The lookup itself failed, with the reason the resolver gave (an unknown domain, a proof
	/// that did not validate, no DNSSEC record).
	Failed(String),
}

impl fmt::Display for NameResolutionError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::NotConfigured => write!(f, "Name resolution is not configured."),
			Self::TimedOut => write!(f, "Looking the name up timed out."),
			Self::Failed(reason) => write!(f, "{}", reason),
		}
	}
}

impl std::error::Error for NameResolutionError {}

/// The bLIP-32 handler as the builder and the node keep it. A wrapper so the builder's `Debug`
/// derive still holds over a trait object. Blocknil patch.
#[derive(Clone)]
pub struct DnsResolverSlot(Arc<dyn DNSResolverMessageHandler + Send + Sync>);

impl DnsResolverSlot {
	pub(crate) fn new(handler: Arc<dyn DNSResolverMessageHandler + Send + Sync>) -> Self {
		Self(handler)
	}

	pub(crate) fn handler(&self) -> Arc<dyn DNSResolverMessageHandler + Send + Sync> {
		Arc::clone(&self.0)
	}
}

impl fmt::Debug for DnsResolverSlot {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "DnsResolverSlot")
	}
}

/// The name resolver as the builder and the node keep it; the same wrapper, for the same reason.
/// Blocknil patch.
#[derive(Clone)]
pub struct NameResolverSlot(Arc<dyn NameResolver + Send + Sync>);

impl NameResolverSlot {
	pub(crate) fn new(resolver: Arc<dyn NameResolver + Send + Sync>) -> Self {
		Self(resolver)
	}

	pub(crate) fn resolver(&self) -> Arc<dyn NameResolver + Send + Sync> {
		Arc::clone(&self.0)
	}
}

impl fmt::Debug for NameResolverSlot {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "NameResolverSlot")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::io::test_utils::InMemoryStore;
	use crate::Builder;

	/// A resolver that answers with the same URI every time, standing in for the wallet's own.
	struct Fixed(&'static str);

	impl NameResolver for Fixed {
		fn resolve_name<'a>(
			&'a self, _name: &'a str,
		) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
			let uri = self.0;
			Box::pin(async move { Ok(uri.to_string()) })
		}
	}

	/// A resolver that fails, the way a provider that can't prove a record does.
	struct Broken;

	impl NameResolver for Broken {
		fn resolve_name<'a>(
			&'a self, name: &'a str,
		) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
			let reason = format!("{name}: no DNSSEC record that validates");
			Box::pin(async move { Err(reason) })
		}
	}

	fn built(resolver: Option<Arc<dyn NameResolver + Send + Sync>>, name: &str) -> crate::Node {
		// A folder of its own per test, so two do not share a store.
		let dir = std::env::temp_dir().join(format!("ldk-node-{name}-{}", std::process::id()));
		let mut builder = Builder::new();
		builder.set_network(bitcoin::Network::Regtest);
		builder.set_entropy_seed_bytes([7; 64]);
		builder.set_log_facade_logger();
		builder.set_storage_dir_path(dir.to_string_lossy().into_owned());
		if let Some(resolver) = resolver {
			builder.set_name_resolver(resolver);
		}
		let node = builder.build_with_store(Arc::new(InMemoryStore::new())).expect("build");
		let _ = std::fs::remove_dir_all(&dir);
		node
	}

	/// The handle the caller sets is the one `resolve_name` uses, and its answer comes back as it
	/// is: the URI is the wallet's to parse, not ours to second-guess (Blocknil patch).
	#[test]
	fn a_configured_resolver_answers_for_the_node() {
		let node = built(Some(Arc::new(Fixed("bitcoin:?lno=lno1test"))), "answers");
		assert_eq!(node.resolve_name("alice@example.com").unwrap(), "bitcoin:?lno=lno1test");
	}

	/// With no resolver set — a node the provider runs, say — there is nothing to ask, and it says
	/// so rather than waiting on a query that will never be sent.
	#[test]
	fn without_a_resolver_it_says_so() {
		let node = built(None, "unconfigured");
		assert_eq!(node.resolve_name("alice@example.com"), Err(NameResolutionError::NotConfigured));
	}

	/// A resolver that can't prove the record gives the reason back, with the name in it.
	#[test]
	fn a_failed_lookup_keeps_its_reason() {
		let node = built(Some(Arc::new(Broken)), "failed");
		match node.resolve_name("alice@example.com") {
			Err(NameResolutionError::Failed(reason)) => {
				assert!(reason.contains("alice@example.com"), "{reason}");
				assert!(reason.contains("DNSSEC"), "{reason}");
			},
			other => panic!("{other:?}"),
		}
	}
}
