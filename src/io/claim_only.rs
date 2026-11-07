// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A store for a claim-only node: everything passes through except the network graph and the
//! scoring data, which are never written.

use std::sync::Arc;

use lightning::util::persist::{
	KVStore, KVStoreSync, NETWORK_GRAPH_PERSISTENCE_KEY, SCORER_PERSISTENCE_KEY,
};

use crate::io::utils::EXTERNAL_PATHFINDING_SCORES_CACHE_KEY;
use crate::types::DynStore;

/// The store a [`ClaimOnlyStore`] wraps, named so callers outside this crate can build one.
pub type Wrapped = Arc<DynStore>;

/// A store that refuses to write the network graph or any scoring data.
///
/// A claim-only node starts with an **empty** graph (see [`crate::NodeBuilder::set_claim_only`]), so
/// anything it persisted there would replace the app's graph with an empty one and force a full
/// re-download. The graph belongs to the app: the app reads it, learns it and prunes it, and the
/// extension must leave it exactly as it found it.
///
/// Reads are passed through — the node still has to read its channel manager and monitors. Only the
/// keys a claim-only node has no business writing are dropped.
pub struct ClaimOnlyStore {
	inner: Arc<DynStore>,
}

impl ClaimOnlyStore {
	/// Wraps the store the node would otherwise write to. The node keeps working on this wrapper:
	/// every read and every write to any other key reaches `inner` unchanged.
	pub fn new(inner: Arc<DynStore>) -> Self {
		Self { inner }
	}

	/// The network graph, the scorer, and the external pathfinding scores cache.
	fn is_off_limits(primary_namespace: &str, secondary_namespace: &str, key: &str) -> bool {
		primary_namespace.is_empty()
			&& secondary_namespace.is_empty()
			&& (key == NETWORK_GRAPH_PERSISTENCE_KEY
				|| key == SCORER_PERSISTENCE_KEY
				|| key == EXTERNAL_PATHFINDING_SCORES_CACHE_KEY)
	}
}

impl KVStoreSync for ClaimOnlyStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, lightning::io::Error> {
		KVStoreSync::read(&*self.inner, primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), lightning::io::Error> {
		if Self::is_off_limits(primary_namespace, secondary_namespace, key) {
			return Ok(());
		}
		KVStoreSync::write(&*self.inner, primary_namespace, secondary_namespace, key, buf)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> Result<(), lightning::io::Error> {
		KVStoreSync::remove(&*self.inner, primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, lightning::io::Error> {
		KVStoreSync::list(&*self.inner, primary_namespace, secondary_namespace)
	}
}

impl KVStore for ClaimOnlyStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> lightning::util::async_poll::AsyncResult<'static, Vec<u8>, lightning::io::Error> {
		KVStore::read(&*self.inner, primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> lightning::util::async_poll::AsyncResult<'static, (), lightning::io::Error> {
		if Self::is_off_limits(primary_namespace, secondary_namespace, key) {
			return Box::pin(async { Ok(()) });
		}
		KVStore::write(&*self.inner, primary_namespace, secondary_namespace, key, buf)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> lightning::util::async_poll::AsyncResult<'static, (), lightning::io::Error> {
		KVStore::remove(&*self.inner, primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> lightning::util::async_poll::AsyncResult<'static, Vec<String>, lightning::io::Error> {
		KVStore::list(&*self.inner, primary_namespace, secondary_namespace)
	}
}
