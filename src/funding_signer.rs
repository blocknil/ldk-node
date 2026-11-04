// Blocknil patch: fund channels from a wallet outside ldk-node.
//
// Upstream ldk-node 0.7.1 pays for every channel open and splice-in out of its own BIP84 wallet.
// LDK itself doesn't care where the money comes from, so the patch adds:
//
// - `Node::splice_in_with_inputs`, which hands LDK splice inputs chosen by the caller;
// - `Node::open_channel_with_external_funding`, which opens a channel whose funding transaction
//   the caller builds when LDK asks for it;
// - a `FundingInputSigner` the caller registers, which signs the splice inputs ldk-node's own
//   wallet doesn't own and builds those funding transactions.
//
// With it, the app's taproot spending wallet pays for channels directly, and the node's on-chain
// wallet can stay empty.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use bitcoin::absolute::LockTime;
use bitcoin::{FeeRate, ScriptBuf, Transaction};

/// Pays for channels from a wallet outside ldk-node.
///
/// Blocknil patch. Register one with [`crate::Node::set_funding_input_signer`] before calling
/// [`crate::Node::splice_in_with_inputs`] or [`crate::Node::open_channel_with_external_funding`].
pub trait FundingInputSigner: Send + Sync {
	/// `tx` is a negotiated splice transaction, with any inputs ldk-node's own wallet owns
	/// already signed. Sign the inputs this signer contributed, with `SIGHASH_ALL`, and return the
	/// transaction. Leave every other input as it is: LDK signs the channel's shared input itself.
	///
	/// The transaction must not be changed in any other way; its content was negotiated with the
	/// channel counterparty.
	fn sign_funding_inputs(&self, tx: Transaction) -> Result<Transaction, ()>;

	/// Builds and signs a transaction that pays exactly `value_sats` to `output_script` (the new
	/// channel's funding output) at `fee_rate`, with `locktime`. Anything else it pays goes back to
	/// this wallet. LDK broadcasts it once the counterparty has signed the first commitment.
	fn build_funding_transaction(
		&self, output_script: ScriptBuf, value_sats: u64, fee_rate: FeeRate, locktime: LockTime,
	) -> Result<Transaction, ()> {
		let _ = (output_script, value_sats, fee_rate, locktime);
		Err(())
	}
}

/// What the node and its event handler share about outside funding: the registered signer, and
/// the channels being opened with it (by `user_channel_id`), with the fee rate to fund them at.
#[derive(Default)]
pub(crate) struct ExternalFunding {
	pub(crate) signer: RwLock<Option<Arc<dyn FundingInputSigner>>>,
	pub(crate) channels: Mutex<HashMap<u128, FeeRate>>,
}

pub(crate) type FundingInputSignerSlot = Arc<ExternalFunding>;
