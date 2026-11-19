// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

// Blocknil patch: channels funded from a wallet outside ldk-node (`FundingInputSigner`), the way
// the app's taproot spending wallet funds them.

mod common;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
	Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
	Witness,
};
use common::{
	configure_chain_source, distribute_funds_unconfirmed, expect_channel_pending_event,
	expect_channel_ready_event, expect_payment_received_event, expect_payment_successful_event,
	expect_splice_negotiated_event, generate_blocks_and_wait, open_channel, open_channel_push_amt,
	premine_and_distribute_funds, random_chain_source, random_config, setup_bitcoind_and_electrsd,
	setup_builder, setup_node, setup_two_nodes, wait_for_channel_ready_to_send, wait_for_tx,
	InMemoryStore, NodePaymentExt, TestChainSource, TestConfig, TestNode,
};
use electrsd::electrum_client::ElectrumApi;
use electrsd::ElectrsD;
use ldk_node::lightning::util::persist::{
	KVStore, PageToken, PaginatedKVStore, PaginatedListResponse,
};
use ldk_node::lightning::util::wallet_utils::ConfirmedUtxo;
use ldk_node::payment::PaymentKind;
use ldk_node::{Builder, Event, FundingInputSigner, NodeError, SpliceFailureReason, UserChannelId};

/// A transaction a signer was asked to sign, and the prevouts the node gave with it.
type SignerCall = (Transaction, Vec<(OutPoint, TxOut)>);

/// A single-key BIP86 (taproot key-spend) wallet outside the node, standing in for the app's
/// spending wallet.
struct TaprootWallet {
	secp: Secp256k1<All>,
	keypair: Keypair,
	/// Every `sign_funding_inputs` call: the transaction and the prevouts the node gave.
	calls: Mutex<Vec<SignerCall>>,
	/// Refuse to sign, as a wallet does that finds something wrong with the transaction.
	refuse: AtomicBool,
	/// The coins `build_funding_transaction` spends.
	funding_coins: Mutex<Vec<(OutPoint, TxOut)>>,
	/// Every funding transaction built, with the fee rate it was asked to pay.
	built: Mutex<Vec<(FeeRate, Transaction)>>,
}

impl TaprootWallet {
	fn new() -> Self {
		let secp = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
		let keypair = Keypair::from_secret_key(&secp, &secret_key);
		Self {
			secp,
			keypair,
			calls: Mutex::new(Vec::new()),
			refuse: AtomicBool::new(false),
			funding_coins: Mutex::new(Vec::new()),
			built: Mutex::new(Vec::new()),
		}
	}

	fn script_pubkey(&self) -> ScriptBuf {
		ScriptBuf::new_p2tr(&self.secp, self.keypair.x_only_public_key().0, None)
	}

	fn address(&self) -> Address {
		Address::from_script(&self.script_pubkey(), Network::Regtest).unwrap()
	}

	/// Signs the inputs at `ours`, given every input's previous output in order.
	fn sign(&self, tx: &mut Transaction, prevouts: &[TxOut], ours: &[usize]) {
		let tweaked = self.keypair.tap_tweak(&self.secp, None).to_keypair();
		for &index in ours {
			let sighash = SighashCache::new(&*tx)
				.taproot_key_spend_signature_hash(
					index,
					&Prevouts::All(prevouts),
					TapSighashType::All,
				)
				.unwrap();
			let message = Message::from_digest(sighash.to_byte_array());
			let signature = self.secp.sign_schnorr_no_aux_rand(&message, &tweaked);
			tx.input[index].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
				signature,
				sighash_type: TapSighashType::All,
			});
		}
	}
}

impl FundingInputSigner for TaprootWallet {
	fn sign_funding_inputs(
		&self, mut tx: Transaction, known_prevouts: Vec<(OutPoint, TxOut)>,
	) -> Result<Transaction, ()> {
		self.calls.lock().unwrap().push((tx.clone(), known_prevouts.clone()));
		if self.refuse.load(Ordering::SeqCst) {
			return Err(());
		}
		let prevouts = tx
			.input
			.iter()
			.map(|txin| {
				known_prevouts
					.iter()
					.find(|(outpoint, _)| *outpoint == txin.previous_output)
					.map(|(_, txout)| txout.clone())
					.ok_or(())
			})
			.collect::<Result<Vec<_>, ()>>()?;
		let script_pubkey = self.script_pubkey();
		let ours: Vec<usize> = (0..tx.input.len())
			.filter(|&index| prevouts[index].script_pubkey == script_pubkey)
			.collect();
		self.sign(&mut tx, &prevouts, &ours);
		Ok(tx)
	}

	fn build_funding_transaction(
		&self, output_script: ScriptBuf, value_sats: u64, fee_rate: FeeRate, locktime: LockTime,
	) -> Result<Transaction, ()> {
		let coins = self.funding_coins.lock().unwrap().clone();
		let input_value: u64 = coins.iter().map(|(_, txout)| txout.value.to_sat()).sum();
		let mut tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: locktime,
			input: coins
				.iter()
				.map(|(outpoint, _)| TxIn {
					previous_output: *outpoint,
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					// A key-spend signature with its sighash byte, for the weight.
					witness: Witness::from_slice(&[[0u8; 65]]),
					..Default::default()
				})
				.collect(),
			output: vec![
				TxOut { value: Amount::from_sat(value_sats), script_pubkey: output_script },
				TxOut { value: Amount::ZERO, script_pubkey: self.script_pubkey() },
			],
		};
		let fee = fee_rate.fee_vb(tx.vsize() as u64).unwrap().to_sat();
		tx.output[1].value = Amount::from_sat(input_value - value_sats - fee);
		let prevouts: Vec<TxOut> = coins.iter().map(|(_, txout)| txout.clone()).collect();
		self.sign(&mut tx, &prevouts, &(0..coins.len()).collect::<Vec<_>>());
		self.built.lock().unwrap().push((fee_rate, tx.clone()));
		Ok(tx)
	}
}

/// Pays `amount` to `wallet` and returns the coin, unconfirmed.
async fn fund_wallet(
	bitcoind: &electrsd::corepc_node::Client, electrsd: &ElectrsD, wallet: &TaprootWallet,
	amount: Amount,
) -> (Transaction, u32) {
	let txid =
		distribute_funds_unconfirmed(bitcoind, &electrsd.client, vec![wallet.address()], amount)
			.await;
	let tx = electrsd.client.transaction_get(&txid).unwrap();
	let vout =
		tx.output.iter().position(|output| output.script_pubkey == wallet.script_pubkey()).unwrap();
	(tx, vout as u32)
}

fn channel_value_sats(node: &TestNode) -> u64 {
	node.list_channels()[0].channel_value_sats
}

/// Two nodes with a confirmed channel of 1,000,000 sats that node A funded from its own wallet,
/// and two confirmed coins of `wallet`'s, of 300,000 and 200,000 sats.
async fn setup_channel_and_coins(
	bitcoind: &electrsd::corepc_node::Node, electrsd: &ElectrsD, node_a: &TestNode,
	node_b: &TestNode, wallet: &TaprootWallet,
) -> (UserChannelId, Vec<(Transaction, u32)>) {
	let address_a = node_a.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![address_a],
		Amount::from_sat(2_000_000),
	)
	.await;
	let coins = vec![
		fund_wallet(&bitcoind.client, electrsd, wallet, Amount::from_sat(300_000)).await,
		fund_wallet(&bitcoind.client, electrsd, wallet, Amount::from_sat(200_000)).await,
	];
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();

	open_channel(node_a, node_b, 1_000_000, false, electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	let user_channel_id = expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());
	(user_channel_id, coins)
}

fn confirmed_utxos(coins: &[(Transaction, u32)]) -> Vec<ConfirmedUtxo> {
	coins
		.iter()
		.map(|(tx, vout)| ConfirmedUtxo::new_p2tr_key_spend(tx.clone(), *vout).unwrap())
		.collect()
}

/// Mines the splice `txid` deep enough to lock and waits until both nodes report it.
async fn confirm_splice(
	bitcoind: &electrsd::corepc_node::Node, electrsd: &ElectrsD, node_a: &TestNode,
	node_b: &TestNode, txid: bitcoin::Txid,
) {
	wait_for_tx(&electrsd.client, txid).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());
}

const SPLICE_FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(1_250);

/// Coins of a taproot wallet outside the node go into the channel: the signer is given the
/// previous output of every input (the channel's funding output, which a signature commits to,
/// and its coins), the splice confirms, and the channel grows by exactly the amount asked, with the
/// rest paid back to the wallet. The node's own wallet pays nothing, and records no payment of
/// its own for the splice; its accounting doesn't cancel the splice either.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn splice_in_from_a_taproot_wallet_outside_the_node() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let (node_a, node_b) = setup_two_nodes(&chain_source, false, false);
	let wallet = Arc::new(TaprootWallet::new());
	let (user_channel_id, coins) =
		setup_channel_and_coins(&bitcoind, &electrsd, &node_a, &node_b, &wallet).await;
	// Without a signer, nobody could sign the coins: refused before anything is negotiated.
	assert_eq!(
		node_a.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		),
		Err(NodeError::ChannelSplicingFailed)
	);
	node_a.set_funding_input_signer(Arc::clone(&wallet) as Arc<dyn FundingInputSigner>);

	let funding_before = node_a.list_channels()[0].funding_txo.unwrap();
	let value_before = channel_value_sats(&node_a);
	let onchain_before = node_a.list_balances().total_onchain_balance_sats;
	let payments_before = node_a.list_all_payments().len();

	node_a
		.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		)
		.unwrap();
	let txo = expect_splice_negotiated_event!(node_a, node_b.node_id());
	wait_for_tx(&electrsd.client, txo.txid).await;
	let splice_tx = electrsd.client.transaction_get(&txo.txid).unwrap();

	// The signer was asked once, about this transaction, and given every input's prevout.
	{
		let calls = wallet.calls.lock().unwrap();
		assert_eq!(calls.len(), 1);
		let (signed_tx, known_prevouts) = &calls[0];
		assert_eq!(signed_tx.compute_txid(), txo.txid);
		assert_eq!(splice_tx.input.len(), 3);
		for txin in &splice_tx.input {
			let (_, prevout) = known_prevouts
				.iter()
				.find(|(outpoint, _)| *outpoint == txin.previous_output)
				.unwrap_or_else(|| panic!("no prevout given for {}", txin.previous_output));
			if txin.previous_output == funding_before {
				assert_eq!(prevout.value.to_sat(), value_before);
				assert!(prevout.script_pubkey.is_p2wsh());
			} else {
				let (tx, vout) = coins
					.iter()
					.find(|(tx, vout)| {
						OutPoint::new(tx.compute_txid(), *vout) == txin.previous_output
					})
					.expect("an input that is neither the channel's nor the wallet's");
				assert_eq!(prevout, &tx.output[*vout as usize]);
			}
		}
	}
	// What the coins held beyond the amount and the fee went back to the wallet.
	let change = splice_tx
		.output
		.iter()
		.find(|output| output.script_pubkey == wallet.script_pubkey())
		.expect("a change output to the wallet");
	let fee = 500_000 - 400_000 - change.value.to_sat();
	assert!(fee > 0 && fee < 2_000, "fee {fee}");

	confirm_splice(&bitcoind, &electrsd, &node_a, &node_b, txo.txid).await;

	assert_eq!(channel_value_sats(&node_a), value_before + 400_000);
	assert_eq!(channel_value_sats(&node_b), value_before + 400_000);
	assert_eq!(node_a.list_balances().total_onchain_balance_sats, onchain_before);
	// The node's own wallet neither paid nor received anything, so it records nothing.
	assert_eq!(node_a.list_all_payments().len(), payments_before);
	assert!(!node_a.list_all_payments().iter().any(|payment| matches!(
		payment.kind,
		PaymentKind::Onchain { txid, .. } if txid == txo.txid
	)));

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}

/// A signer that refuses ends the splice, as a failure the application is told of, and nothing is
/// held: the node's wallet is as it was, and the same coins then go into a splice that completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn refused_external_splice_is_abandoned_without_holding_coins() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let (node_a, node_b) = setup_two_nodes(&chain_source, false, false);
	let wallet = Arc::new(TaprootWallet::new());
	let (user_channel_id, coins) =
		setup_channel_and_coins(&bitcoind, &electrsd, &node_a, &node_b, &wallet).await;
	node_a.set_funding_input_signer(Arc::clone(&wallet) as Arc<dyn FundingInputSigner>);

	let value_before = channel_value_sats(&node_a);
	let onchain_before = node_a.list_balances().spendable_onchain_balance_sats;
	let payments_before = node_a.list_all_payments().len();

	wallet.refuse.store(true, Ordering::SeqCst);
	node_a
		.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		)
		.unwrap();
	match tokio::time::timeout(std::time::Duration::from_secs(60), node_a.next_event_async())
		.await
		.expect("no event after the refusal")
	{
		Event::SpliceNegotiationFailed { counterparty_node_id, .. } => {
			assert_eq!(counterparty_node_id, node_b.node_id());
			node_a.event_handled().unwrap();
		},
		event => panic!("unexpected event {event:?}"),
	}
	assert_eq!(wallet.calls.lock().unwrap().len(), 1);
	assert_eq!(channel_value_sats(&node_a), value_before);
	node_a.sync_wallets().unwrap();
	assert_eq!(node_a.list_balances().spendable_onchain_balance_sats, onchain_before);
	assert_eq!(node_a.list_all_payments().len(), payments_before);

	// The same coins, now signed: nothing kept them back.
	wallet.refuse.store(false, Ordering::SeqCst);
	node_a
		.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		)
		.unwrap();
	let txo = expect_splice_negotiated_event!(node_a, node_b.node_id());
	confirm_splice(&bitcoind, &electrsd, &node_a, &node_b, txo.txid).await;
	assert_eq!(channel_value_sats(&node_a), value_before + 400_000);
	assert_eq!(node_a.list_balances().spendable_onchain_balance_sats, onchain_before);

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}

/// A store a test can stop writing to, as a process killed at that point stops: what it holds
/// from then on is what the node had written before.
#[derive(Clone)]
struct KillableStore {
	inner: Arc<InMemoryStore>,
	killed: Arc<AtomicBool>,
}

impl KillableStore {
	fn new() -> Self {
		Self { inner: Arc::new(InMemoryStore::new()), killed: Arc::new(AtomicBool::new(false)) }
	}

	/// From now on, every write and removal is dropped.
	fn kill(&self) {
		self.killed.store(true, Ordering::Release);
	}

	/// The same records, written to again: the node's state as the killed process left it.
	fn restarted(&self) -> Self {
		Self { inner: Arc::clone(&self.inner), killed: Arc::new(AtomicBool::new(false)) }
	}
}

impl KVStore for KillableStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, lightning::io::Error>> + 'static + Send {
		KVStore::read(&*self.inner, primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		// The inner store writes as soon as it is asked, so a dropped write is never asked for.
		let write = (!self.killed.load(Ordering::Acquire)).then(|| {
			KVStore::write(&*self.inner, primary_namespace, secondary_namespace, key, buf)
		});
		async move {
			match write {
				Some(write) => write.await,
				None => Ok(()),
			}
		}
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		let remove = (!self.killed.load(Ordering::Acquire)).then(|| {
			KVStore::remove(&*self.inner, primary_namespace, secondary_namespace, key, lazy)
		});
		async move {
			match remove {
				Some(remove) => remove.await,
				None => Ok(()),
			}
		}
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, lightning::io::Error>> + 'static + Send {
		KVStore::list(&*self.inner, primary_namespace, secondary_namespace)
	}
}

impl PaginatedKVStore for KillableStore {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> impl Future<Output = Result<PaginatedListResponse, lightning::io::Error>> + 'static + Send
	{
		PaginatedKVStore::list_paginated(
			&*self.inner,
			primary_namespace,
			secondary_namespace,
			page_token,
		)
	}
}

/// A signer that, asked to sign, says so and then waits for the test, which kills the node
/// meanwhile: the app's process killed while its wallet signs.
struct KilledWhileSigning {
	asked: Mutex<mpsc::Sender<()>>,
	resume: Mutex<mpsc::Receiver<()>>,
}

impl FundingInputSigner for KilledWhileSigning {
	fn sign_funding_inputs(
		&self, _tx: Transaction, _known_prevouts: Vec<(OutPoint, TxOut)>,
	) -> Result<Transaction, ()> {
		self.asked.lock().unwrap().send(()).unwrap();
		let _ = self.resume.lock().unwrap().recv_timeout(Duration::from_secs(120));
		// The process is dead by now: nothing this returns reaches the store or the peer.
		Err(())
	}
}

fn build_node_with_store(
	chain_source: &TestChainSource, config: &TestConfig, store: KillableStore,
) -> TestNode {
	setup_builder!(builder, config.node_config);
	configure_chain_source(chain_source, &mut builder, config);
	// `into` as in `common::setup_node`, for the uniffi build.
	#[allow(clippy::useless_conversion)]
	builder.build_with_store(config.node_entropy.into(), store).unwrap()
}

/// Waits for the event `matches` picks, handling the ones before it.
async fn next_event_matching(node: &TestNode, matches: impl Fn(&Event) -> bool) -> Event {
	tokio::time::timeout(Duration::from_secs(90), async {
		loop {
			let event = node.next_event_async().await;
			println!("{} got event {:?}", node.node_id(), event);
			node.event_handled().unwrap();
			if matches(&event) {
				return event;
			}
		}
	})
	.await
	.expect("the event never came")
}

/// Node A splices in coins of `wallet`'s, and its process is killed while the wallet signs them:
/// its store then holds the negotiated round, unsigned, which LDK persists before it asks for the
/// signatures. Node A has a 1,000,000-sat channel with node B, which holds 300,000 sats of it.
/// Returns node A's store, its config, node B, and the channel's value before the splice.
async fn kill_node_while_its_wallet_signs_a_splice(
	bitcoind: &electrsd::corepc_node::Node, electrsd: &ElectrsD,
	chain_source: &TestChainSource<'_>, wallet: &TaprootWallet,
) -> (KillableStore, TestConfig, TestNode, u64) {
	let config_a = random_config();
	let store = KillableStore::new();
	let node_a = build_node_with_store(chain_source, &config_a, store.clone());
	let (asked_sender, asked) = mpsc::channel();
	let (resume, resume_receiver) = mpsc::channel();
	node_a.set_funding_input_signer(Arc::new(KilledWhileSigning {
		asked: Mutex::new(asked_sender),
		resume: Mutex::new(resume_receiver),
	}));
	node_a.start().unwrap();
	let node_b = setup_node(chain_source, random_config());

	let address_a = node_a.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![address_a],
		Amount::from_sat(2_000_000),
	)
	.await;
	let coins = vec![
		fund_wallet(&bitcoind.client, electrsd, wallet, Amount::from_sat(300_000)).await,
		fund_wallet(&bitcoind.client, electrsd, wallet, Amount::from_sat(200_000)).await,
	];
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	open_channel_push_amt(&node_a, &node_b, 1_000_000, Some(300_000_000), false, electrsd).await;
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	let user_channel_id = expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());
	let value_before = channel_value_sats(&node_a);

	node_a
		.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		)
		.unwrap();
	asked.recv_timeout(Duration::from_secs(60)).expect("node A never asked for the signatures");

	// The kill: nothing more is written, and nothing more reaches node B.
	store.kill();
	node_a.disconnect(node_b.node_id()).unwrap();
	resume.send(()).unwrap();
	node_a.stop().unwrap();
	drop(node_a);
	(store, config_a, node_b, value_before)
}

/// The app is killed while its wallet signs a splice, and the next start is the notification
/// extension's, to receive a payment: a node with no signer. The round LDK asks it to sign again
/// is cancelled, which frees the channel, and the payment is claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_splice_regenerated_without_a_signer_is_cancelled_and_a_payment_is_claimed() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let wallet = TaprootWallet::new();
	let (store, config_a, node_b, value_before) =
		kill_node_while_its_wallet_signs_a_splice(&bitcoind, &electrsd, &chain_source, &wallet)
			.await;

	let node_a = build_node_with_store(&chain_source, &config_a, store.restarted());
	node_a.start().unwrap();
	// The round LDK asked to sign again is cancelled, by this node.
	let failed = next_event_matching(&node_a, |event| {
		matches!(event, Event::SpliceNegotiationFailed { .. })
	})
	.await;
	assert!(matches!(
		failed,
		Event::SpliceNegotiationFailed { reason: Some(SpliceFailureReason::LocallyCanceled), .. }
	));

	wait_for_channel_ready_to_send(&node_b, &node_a, 50_000_000).await;
	let payment_id = node_b.spontaneous_payment().send(50_000_000, node_a.node_id(), None).unwrap();
	let received = next_event_matching(&node_a, |event| {
		matches!(event, Event::PaymentReceived { .. } | Event::PaymentFailed { .. })
	})
	.await;
	assert!(matches!(received, Event::PaymentReceived { amount_msat: 50_000_000, .. }));
	let sent = next_event_matching(&node_b, |event| {
		matches!(event, Event::PaymentSuccessful { .. } | Event::PaymentFailed { .. })
	})
	.await;
	assert!(matches!(sent, Event::PaymentSuccessful { payment_id: id, .. } if id == payment_id));
	assert_eq!(channel_value_sats(&node_a), value_before);

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}

/// The app is killed while its wallet signs a splice, and starts again with its signer registered
/// before `start`: LDK asks again for the round's signatures, the wallet signs, and the splice
/// completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_splice_regenerated_with_a_signer_is_signed_on_start() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let wallet = Arc::new(TaprootWallet::new());
	let (store, config_a, node_b, value_before) =
		kill_node_while_its_wallet_signs_a_splice(&bitcoind, &electrsd, &chain_source, &wallet)
			.await;

	let node_a = build_node_with_store(&chain_source, &config_a, store.restarted());
	node_a.set_funding_input_signer(Arc::clone(&wallet) as Arc<dyn FundingInputSigner>);
	node_a.start().unwrap();
	let txo = expect_splice_negotiated_event!(node_a, node_b.node_id());
	assert_eq!(wallet.calls.lock().unwrap().len(), 1);
	confirm_splice(&bitcoind, &electrsd, &node_a, &node_b, txo.txid).await;
	assert_eq!(channel_value_sats(&node_a), value_before + 400_000);

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}

/// Fee-bumping an external splice keeps its coins and its amount: the higher fee comes out of the
/// change, the signer is asked again for the replacement, and the replacement confirms with the
/// channel grown by exactly the amount asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn external_splice_fee_bump_is_paid_from_its_change() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let (node_a, node_b) = setup_two_nodes(&chain_source, false, false);
	let wallet = Arc::new(TaprootWallet::new());
	let (user_channel_id, coins) =
		setup_channel_and_coins(&bitcoind, &electrsd, &node_a, &node_b, &wallet).await;
	node_a.set_funding_input_signer(Arc::clone(&wallet) as Arc<dyn FundingInputSigner>);
	let value_before = channel_value_sats(&node_a);
	let onchain_before = node_a.list_balances().total_onchain_balance_sats;

	node_a
		.splice_in_with_inputs(
			&user_channel_id,
			node_b.node_id(),
			400_000,
			confirmed_utxos(&coins),
			wallet.script_pubkey(),
			SPLICE_FEE_RATE,
		)
		.unwrap();
	let first = expect_splice_negotiated_event!(node_a, node_b.node_id());
	wait_for_tx(&electrsd.client, first.txid).await;
	let first_tx = electrsd.client.transaction_get(&first.txid).unwrap();

	node_a
		.bump_channel_funding_fee(
			&user_channel_id,
			node_b.node_id(),
			Some(FeeRate::from_sat_per_kwu(2_500)),
		)
		.unwrap();
	let second = expect_splice_negotiated_event!(node_a, node_b.node_id());
	assert_ne!(second.txid, first.txid);
	wait_for_tx(&electrsd.client, second.txid).await;
	let second_tx = electrsd.client.transaction_get(&second.txid).unwrap();

	{
		let calls = wallet.calls.lock().unwrap();
		assert_eq!(calls.len(), 2);
		assert_eq!(calls[1].0.compute_txid(), second.txid);
	}
	let change = |tx: &Transaction| {
		tx.output
			.iter()
			.find(|output| output.script_pubkey == wallet.script_pubkey())
			.expect("a change output to the wallet")
			.value
	};
	assert!(change(&second_tx) < change(&first_tx), "the bump is paid from the change");
	let spent = |tx: &Transaction| {
		let mut outpoints: Vec<OutPoint> =
			tx.input.iter().map(|txin| txin.previous_output).collect();
		outpoints.sort();
		outpoints
	};
	assert_eq!(spent(&second_tx), spent(&first_tx), "the same coins");

	confirm_splice(&bitcoind, &electrsd, &node_a, &node_b, second.txid).await;
	assert_eq!(node_a.list_channels()[0].funding_txo.unwrap().txid, second.txid);
	assert_eq!(channel_value_sats(&node_a), value_before + 400_000);
	assert_eq!(node_a.list_balances().total_onchain_balance_sats, onchain_before);

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}

/// A channel whose funding transaction a wallet outside the node builds and signs, at the fee rate
/// the caller asked for: the funding transaction pays exactly the channel's value at that rate,
/// confirms, and the channel carries a payment. The node's own wallet, which only holds the anchor
/// reserve, pays nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn channel_funded_by_a_wallet_outside_the_node_at_a_given_fee_rate() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = random_chain_source(&bitcoind, &electrsd);
	let (node_a, node_b) = setup_two_nodes(&chain_source, false, false);
	let wallet = Arc::new(TaprootWallet::new());

	// Node A's own wallet holds little more than the anchor reserve.
	let address_a = node_a.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![address_a],
		Amount::from_sat(100_000),
	)
	.await;
	let (coin_tx, vout) =
		fund_wallet(&bitcoind.client, &electrsd, &wallet, Amount::from_sat(1_000_000)).await;
	wallet
		.funding_coins
		.lock()
		.unwrap()
		.push((OutPoint::new(coin_tx.compute_txid(), vout), coin_tx.output[vout as usize].clone()));
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	let onchain_before = node_a.list_balances().total_onchain_balance_sats;

	// Without a signer there is nobody to build the funding transaction.
	let node_b_address = node_b.listening_addresses().unwrap().first().unwrap().clone();
	assert!(node_a
		.open_channel_with_external_funding(node_b.node_id(), node_b_address.clone(), 500_000, None)
		.is_err());
	node_a.set_funding_input_signer(Arc::clone(&wallet) as Arc<dyn FundingInputSigner>);

	// A rate unlike the node's own estimate, so that the test tells them apart.
	let fee_rate = FeeRate::from_sat_per_kwu(3_250);
	assert_ne!(node_a.channel_funding_fee_rate(), fee_rate);
	node_a
		.open_channel_with_external_funding(
			node_b.node_id(),
			node_b_address,
			500_000,
			Some(fee_rate),
		)
		.unwrap();
	let funding_txo = expect_channel_pending_event!(node_a, node_b.node_id());
	expect_channel_pending_event!(node_b, node_a.node_id());
	wait_for_tx(&electrsd.client, funding_txo.txid).await;

	let funding_tx = electrsd.client.transaction_get(&funding_txo.txid).unwrap();
	{
		let built = wallet.built.lock().unwrap();
		assert_eq!(built.len(), 1);
		assert_eq!(built[0].0, fee_rate);
		assert_eq!(built[0].1.compute_txid(), funding_txo.txid);
	}
	assert_eq!(funding_tx.output[funding_txo.vout as usize].value.to_sat(), 500_000);
	let fee = 1_000_000 - funding_tx.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
	assert_eq!(fee, fee_rate.fee_vb(funding_tx.vsize() as u64).unwrap().to_sat());

	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;
	node_a.sync_wallets().unwrap();
	node_b.sync_wallets().unwrap();
	expect_channel_ready_event!(node_a, node_b.node_id());
	expect_channel_ready_event!(node_b, node_a.node_id());
	assert_eq!(channel_value_sats(&node_a), 500_000);
	assert_eq!(node_a.list_balances().total_onchain_balance_sats, onchain_before);

	// The channel is usable.
	wait_for_channel_ready_to_send(&node_a, &node_b, 100_000_000).await;
	let payment_id =
		node_a.spontaneous_payment().send(100_000_000, node_b.node_id(), None).unwrap();
	expect_payment_successful_event!(node_a, payment_id, None);
	expect_payment_received_event!(node_b, 100_000_000);

	node_a.stop().unwrap();
	node_b.stop().unwrap();
}
