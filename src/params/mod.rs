#![allow(non_camel_case_types)]

use ark_ff::PrimeField;

pub mod mimc_220_3_bn254;

pub fn round_keys_contants_to_vec<F: PrimeField>(round_keys: &[&str]) -> Vec<F>
where
    F::Err: core::fmt::Debug,
{
    round_keys
        .into_iter()
        .map(|e| F::from_str(e).unwrap())
        .collect()
}
