//! Round constants are generated from
//! https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js
#![allow(non_camel_case_types)]

use ark_ff::PrimeField;

#[cfg(feature = "mimc_220_3_bls12_381")]
pub mod mimc_220_3_bls12_381;
#[cfg(feature = "mimc_220_3_bn254")]
pub mod mimc_220_3_bn254;

pub fn round_keys_contants_to_vec<F: PrimeField>(round_keys: &[&str]) -> Vec<F>
where
    F::Err: core::fmt::Debug,
{
    round_keys
        .iter()
        .map(|e| F::from_str(e).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_ff::{to_bytes, One, Zero};

    use crate::{MiMC, CRH};

    use super::{
        mimc_220_3_bn254::{MIMC_220_3_BN254_PARAMS, MIMC_220_3_BN254_ROUND_KEYS},
        round_keys_contants_to_vec,
    };

    #[test]
    fn correct_hash_result_params() {
        let param = MiMC::<Fr, MIMC_220_3_BN254_PARAMS>::new(
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_220_3_BN254_ROUND_KEYS),
        );

        let result = <CRH<Fr, MIMC_220_3_BN254_PARAMS> as TwoToOneCRH>::evaluate(
            &param,
            &to_bytes!(Fr::one()).unwrap(),
            &to_bytes!(Fr::zero()).unwrap(),
        )
        .unwrap();

        assert_eq!(
            result,
            Fr::from_str(
                "13403990812567987967336759851318987973794445269548215402779394294754792373527"
            )
            .unwrap()
        );
    }
}
