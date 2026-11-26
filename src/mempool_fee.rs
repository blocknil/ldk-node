// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Blocknil patch: fee estimates for transactions that can wait, capped by what the mempool asks.
//!
//! Bitcoin Core's `estimatesmartfee` reads the recent past and stays high while the mempool is
//! nearly empty (5.3 sat/vB for the next block on 2026-11-05, with under a block's worth paying
//! 1 sat/vB or more), so funding transactions overpaid several times over. The bitcoind chain
//! source builds a fee histogram from the mempool entries its poll caches, the Electrum chain
//! source asks its server for one (`mempool.get_fee_histogram`), and the targets that can wait pay
//! the cheaper of Core's estimate and the mempool's.

use bitcoin::FeeRate;
use lightning::chain::chaininterface::{
	ConfirmationTarget as LdkConfirmationTarget, FEERATE_FLOOR_SATS_PER_KW,
};

use crate::fee_estimator::{get_num_block_defaults_for_target, ConfirmationTarget};

/// The fee rate, in sat/vB, that puts a transaction within `num_blocks` blocks of the mempool's
/// top, from `(rate, vsize)` pairs, highest rate first, each the vsize paying at least that rate
/// and less than the pair before.
///
/// Within a pair the rate is interpolated: the share of it that fits above the cut sits between
/// its rate and the one above it. Zero when the whole mempool fits: the floor will do.
pub(crate) fn mempool_fee_rate_sat_vb(histogram: &[(f64, u64)], num_blocks: usize) -> f64 {
	const BLOCK_VSIZE: f64 = 1_000_000.0;
	let depth = BLOCK_VSIZE * num_blocks.max(1) as f64;
	let mut above = 0.0;
	let mut upper: Option<f64> = None;
	for &(rate, vsize) in histogram {
		let size = vsize as f64;
		if size > 0.0 && above + size >= depth {
			let top = upper.unwrap_or(rate * 2.0).max(rate);
			let into = (depth - above) / size;
			return top - (top - rate) * into;
		}
		above += size;
		upper = Some(rate);
	}
	0.0
}

/// The targets whose transactions can wait their turn, which take the cheaper of Core's estimate
/// and the mempool's. Commitment fees (agreed with the peer, which force-closes on one it finds too
/// low), urgent claims and close negotiation keep Core's.
pub(crate) fn may_use_mempool_rate(target: ConfirmationTarget) -> bool {
	matches!(
		target,
		ConfirmationTarget::OnchainPayment
			| ConfirmationTarget::ChannelFunding
			| ConfirmationTarget::Lightning(LdkConfirmationTarget::OutputSpendingFee)
	)
}

/// `estimate` for `target`, lowered to what `histogram` (see [`mempool_fee_rate_sat_vb`]) asks
/// for the target's number of blocks, never below the relay floor. Unchanged for a target that
/// can't wait, or without a histogram.
pub(crate) fn capped_by_mempool(
	target: ConfirmationTarget, estimate: FeeRate, histogram: Option<&[(f64, u64)]>,
) -> FeeRate {
	match histogram {
		Some(histogram) if may_use_mempool_rate(target) => {
			let num_blocks = get_num_block_defaults_for_target(target);
			let mempool_sat_kwu =
				(mempool_fee_rate_sat_vb(histogram, num_blocks) * 250.0).ceil() as u64;
			let mempool_sat_kwu = mempool_sat_kwu.max(FEERATE_FLOOR_SATS_PER_KW as u64);
			FeeRate::from_sat_per_kwu(estimate.to_sat_per_kwu().min(mempool_sat_kwu))
		},
		_ => estimate,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Electrum's power-of-two buckets, as an Electrum server answers them.
	const QUIET: [(f64, u64); 10] = [
		(511.0, 170),
		(255.0, 0),
		(127.0, 492),
		(63.0, 1260),
		(31.0, 3946),
		(15.0, 25910),
		(7.0, 40000),
		(3.0, 135571),
		(1.0, 147369),
		(0.0, 22686053),
	];

	#[test]
	fn a_quiet_mempool_needs_next_to_nothing() {
		// Under a block pays 1 sat/vB or more, so the next block is reached below 1.
		assert!(mempool_fee_rate_sat_vb(&QUIET, 1) < 1.0);
		assert!(mempool_fee_rate_sat_vb(&QUIET, 12) < 1.0);
	}

	#[test]
	fn a_busy_mempool_is_read_at_the_cut() {
		// 2 MvB at 20 sat/vB or more, then 3 MvB at 10-20: the next block is 20+, the third ~16.7.
		let busy = [(40.0, 500_000), (20.0, 1_500_000), (10.0, 3_000_000), (1.0, 10_000_000)];
		let next = mempool_fee_rate_sat_vb(&busy, 1);
		assert!(next > 20.0 && next < 40.0, "{next}");
		let third = mempool_fee_rate_sat_vb(&busy, 3);
		assert!((third - 16.67).abs() < 0.1, "{third}");
		assert_eq!(mempool_fee_rate_sat_vb(&busy, 100), 0.0, "everything fits");
	}

	#[test]
	fn an_empty_histogram_means_the_floor() {
		assert_eq!(mempool_fee_rate_sat_vb(&[], 1), 0.0);
	}

	#[test]
	fn only_targets_that_can_wait_are_capped() {
		let kwu = FeeRate::from_sat_per_kwu;
		let core = kwu(5_000);
		let empty: &[(f64, u64)] = &[];
		for target in crate::fee_estimator::get_all_conf_targets() {
			let capped = capped_by_mempool(target, core, Some(empty));
			if may_use_mempool_rate(target) {
				// An empty mempool asks nothing: the relay floor.
				assert_eq!(capped, kwu(FEERATE_FLOOR_SATS_PER_KW as u64), "{target:?}");
			} else {
				assert_eq!(capped, core, "{target:?}");
			}
			// Without a histogram, Core's estimate stands.
			assert_eq!(capped_by_mempool(target, core, None), core, "{target:?}");
		}
		assert!(may_use_mempool_rate(ConfirmationTarget::OnchainPayment));
		assert!(may_use_mempool_rate(ConfirmationTarget::ChannelFunding));
		assert!(may_use_mempool_rate(LdkConfirmationTarget::OutputSpendingFee.into()));
	}

	#[test]
	fn the_mempool_never_raises_an_estimate() {
		let kwu = FeeRate::from_sat_per_kwu;
		// 2 MvB at 40 sat/vB all fits in the next 6 blocks: the floor, under Core's 5 sat/vB.
		let busy: &[(f64, u64)] = &[(40.0, 2_000_000)];
		let target = ConfirmationTarget::OnchainPayment;
		assert_eq!(capped_by_mempool(target, kwu(1_250), Some(busy)), kwu(253));
		// 12 MvB at 40 sat/vB: 6 blocks deep it asks 60 sat/vB, more than Core's 5: Core's stands.
		let full: &[(f64, u64)] = &[(40.0, 12_000_000)];
		assert_eq!(capped_by_mempool(target, kwu(1_250), Some(full)), kwu(1_250));
		// 12 MvB at 4 sat/vB asks 6 sat/vB 6 blocks deep, under Core's 20: the mempool's rate.
		let some: &[(f64, u64)] = &[(4.0, 12_000_000)];
		assert_eq!(capped_by_mempool(target, kwu(5_000), Some(some)), kwu(1_500));
	}
}
