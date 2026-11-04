// Blocknil patch: splice coins from a wallet outside ldk-node into a channel.
//
// Upstream ldk-node 0.7.1 only splices in coins from its own BIP84 wallet: `Node::splice_in`
// selects them, and the `FundingTransactionReadyForSigning` handler signs only the inputs that
// wallet owns. LDK itself takes any inputs (`SpliceContribution::SpliceIn { inputs, .. }`), so the
// patch adds two things:
//
// - `Node::splice_in_with_inputs`, which hands LDK inputs chosen by the caller, and
// - a `FundingInputSigner` the caller registers, which the event handler asks to sign whatever
//   ldk-node's own wallet did not.
//
// With it, the app's taproot spending wallet pays for a splice directly, and the node's on-chain
// wallet can stay empty.

use std::sync::{Arc, RwLock};

use bitcoin::Transaction;

/// Signs the inputs a wallet outside ldk-node contributed to a channel funding transaction.
///
/// Blocknil patch. Register one with [`crate::Node::set_funding_input_signer`] before calling
/// [`crate::Node::splice_in_with_inputs`].
pub trait FundingInputSigner: Send + Sync {
	/// `tx` is the negotiated funding transaction, with any inputs ldk-node's own wallet owns
	/// already signed. Sign the inputs this signer contributed, with `SIGHASH_ALL`, and return the
	/// transaction. Leave every other input as it is: LDK signs the channel's shared input itself.
	///
	/// The transaction must not be changed in any other way; its content was negotiated with the
	/// channel counterparty.
	fn sign_funding_inputs(&self, tx: Transaction) -> Result<Transaction, ()>;
}

/// Where the registered signer lives, shared between the node and its event handler.
pub(crate) type FundingInputSignerSlot = Arc<RwLock<Option<Arc<dyn FundingInputSigner>>>>;
