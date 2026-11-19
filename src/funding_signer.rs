// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

// Blocknil patch: splice coins from a wallet outside ldk-node into a channel.
//
// Upstream ldk-node only splices in coins from its own wallet: `Node::splice_in` has them chosen by
// that wallet, and the `FundingTransactionReadyForSigning` handler signs only the inputs that wallet
// owns. LDK itself takes any confirmed coins, so the patch adds two things:
//
// - `Node::splice_in_with_inputs`, which hands LDK coins chosen by the caller, and
// - a `FundingInputSigner` the caller registers, which the event handler asks to sign the inputs
//   of this node's contribution that its own wallet does not own.
//
// With it, a spending wallet outside the node (a taproot one, say) pays for a splice directly, and
// the node's on-chain wallet can stay empty.

use std::sync::{Arc, RwLock};

use bitcoin::psbt::Psbt;
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut};
use lightning::chain::ClaimId;
use lightning::ln::funding::{FundingContribution, FundingContributionError, FundingTemplate};
use lightning::util::wallet_utils::{CoinSelection, CoinSelectionSourceSync, ConfirmedUtxo, Input};

/// Signs the inputs a wallet outside ldk-node contributed to a channel's funding transaction.
///
/// Blocknil patch. Register one with [`crate::Node::set_funding_input_signer`] before
/// [`crate::Node::start`]: LDK asks again, when the node starts, for the signatures of a splice
/// whose signing a stop interrupted, and a node with no signer registered then cancels it.
pub trait FundingInputSigner: Send + Sync {
	/// `tx` is a negotiated splice transaction, with the inputs ldk-node's own wallet owns already
	/// signed. Sign the inputs this signer contributed, with `SIGHASH_ALL`, and return the
	/// transaction. Leave every other input as it is: LDK signs the channel's shared input itself.
	///
	/// The transaction must not be changed in any other way; its content was negotiated with the
	/// channel counterparty. An error cancels the splice.
	///
	/// `known_prevouts` are the outputs the node knows the inputs spend: the channel's current
	/// funding output (the shared input) and the coins this node contributed. Signing a Taproot
	/// input needs every input's previous output; these need not be looked up, and the channel's
	/// funding can't be when it never reached the chain. Inputs the counterparty contributed are
	/// not among them.
	// `()` as in r8's trait, which the app implements, and as LDK's own wallet traits do.
	#[allow(clippy::result_unit_err)]
	fn sign_funding_inputs(
		&self, tx: Transaction, known_prevouts: Vec<(OutPoint, TxOut)>,
	) -> Result<Transaction, ()>;
}

/// What the node and its event handler share about funding from outside the node: the registered
/// signer.
#[derive(Default)]
pub(crate) struct ExternalFunding {
	pub(crate) signer: RwLock<Option<Arc<dyn FundingInputSigner>>>,
}

/// Builds a contribution adding `value_added` to a channel from `inputs`, which a wallet outside
/// the node owns, with what is left over paid to `change_script`.
///
/// Every input is spent, as LDK 0.2's `SpliceContribution::SpliceIn { inputs, change_script, .. }`
/// spent them. The contribution is a coin-selected one, as [`FundingTemplate::splice_in`] builds
/// from the node's own wallet, so that a later fee adjustment (an RBF, or the counterparty's
/// feerate when it initiates) is paid from the change rather than from the amount added.
pub(crate) fn external_splice_in_contribution(
	template: FundingTemplate, value_added: Amount, inputs: Vec<ConfirmedUtxo>,
	change_script: ScriptBuf, feerate: FeeRate, max_feerate: FeeRate,
) -> Result<FundingContribution, FundingContributionError> {
	// The fee depends only on the transaction's weight, never on the values it moves, so LDK's own
	// estimate for these inputs and a change output is read from a contribution built with them.
	let fee = template
		.clone()
		.without_prior_contribution(feerate, max_feerate)
		.add_inputs(inputs.clone())?
		.add_output(TxOut { value: Amount::ZERO, script_pubkey: change_script.clone() })
		.build()?
		.estimated_fee();
	let input_value: Amount = inputs.iter().map(|input| input.output().value).sum();
	let change_value = input_value
		.checked_sub(value_added)
		.and_then(|value| value.checked_sub(fee))
		.ok_or(FundingContributionError::CoinSelectionFailed)?;
	// A change output below dust is left out; what it would have held goes to the channel.
	let change_output = TxOut { value: change_value, script_pubkey: change_script };
	let change_output =
		(change_value >= change_output.script_pubkey.minimal_non_dust()).then_some(change_output);

	template
		.without_prior_contribution(feerate, max_feerate)
		.with_coin_selection_source_sync(ChosenCoins(CoinSelection {
			confirmed_utxos: inputs,
			change_output,
		}))
		.add_value(value_added)?
		.build()
}

/// The coins and change a caller chose, offered to LDK as the outcome of its coin selection.
struct ChosenCoins(CoinSelection);

impl CoinSelectionSourceSync for ChosenCoins {
	fn select_confirmed_utxos(
		&self, _claim_id: Option<ClaimId>, _must_spend: Vec<Input>, _must_pay_to: &[TxOut],
		_target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
	) -> Result<CoinSelection, ()> {
		Ok(self.0.clone())
	}

	// Funding inputs are signed when LDK asks for the funding transaction's signatures, through
	// `FundingInputSigner`, never here.
	fn sign_psbt(&self, _psbt: Psbt) -> Result<Transaction, ()> {
		Err(())
	}
}
