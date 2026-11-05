// Blocknil patch. Pure, so the wallet core includes this same file (`#[path]`) and tests it there:
// this crate's tests can't run inside the wallet's workspace.

/// Blocknil patch: the fee rate, in sat/vB, that puts a transaction within `num_blocks` blocks of
/// the mempool's top, from an Electrum `mempool.get_fee_histogram`: `(rate, vsize)` pairs, highest
/// rate first, each the vsize paying at least that rate and less than the pair before. Bitcoin
/// Core's `estimatesmartfee` reads the recent past and stays high while the mempool is nearly
/// empty (5.3 sat/vB for the next block on 2026-11-05, with under a block's worth paying 1 sat/vB
/// or more), so funding transactions overpaid several times over.
///
/// Within a bucket the rate is interpolated: the share of the bucket that fits above the cut sits
/// between its rate and the one above it. Zero when the whole mempool fits: the floor will do.
pub fn mempool_fee_rate_sat_vb(histogram: &[(f64, u64)], num_blocks: usize) -> f64 {
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
}
