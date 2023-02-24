//! Round constants are generated from
//! https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js
#![allow(non_camel_case_types)]

use ark_ff::PrimeField;

#[cfg(feature = "mimc-5-218-bls12-377")]
pub mod mimc_5_218_bls12_377;
#[cfg(feature = "mimc-5-220-bls12-381")]
pub mod mimc_5_220_bls12_381;
#[cfg(feature = "mimc-5-220-bn254")]
pub mod mimc_5_220_bn254;
#[cfg(feature = "mimc-7-90-bls12-377")]
pub mod mimc_7_90_bls12_377;
#[cfg(feature = "mimc-7-91-bls12-381")]
pub mod mimc_7_91_bls12_381;
#[cfg(feature = "mimc-7-91-bn254")]
pub mod mimc_7_91_bn254;

pub fn round_keys_contants_to_vec<F: PrimeField>(round_keys: &[&str]) -> Vec<F>
where
    F::Err: core::fmt::Debug,
{
    round_keys.iter().map(|e| F::from_str(e).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use std::{error::Error, str::FromStr};

    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::TwoToOneCRHScheme;
    use ark_ff::Zero;

    use crate::{
        params::{
            mimc_5_220_bn254::{MIMC_5_220_BN254_PARAMS, MIMC_5_220_BN254_ROUND_KEYS},
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCFeistelCRH, MiMCNonFeistelCRH,
    };

    #[test]
    fn correct_hash_result_params_feistel() -> Result<(), Box<dyn Error>> {
        let param = MiMC::<Fr, MIMC_5_220_BN254_PARAMS>::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_5_220_BN254_ROUND_KEYS),
        );

        let result = <MiMCFeistelCRH<Fr, MIMC_5_220_BN254_PARAMS> as TwoToOneCRHScheme>::evaluate(
            &param,
            &Fr::from(1),
            &Fr::from(0),
        )?;

        assert_eq!(
            result,
            Fr::from_str(
                "13403990812567987967336759851318987973794445269548215402779394294754792373527"
            )
            .unwrap()
        );

        Ok(())
    }

    #[test]
    fn correct_hash_result_params_non_feistel() -> Result<(), Box<dyn Error>> {
        let param = MiMC::<Fr, MIMC_7_91_BN254_PARAMS>::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        );

        let result =
            <MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS> as TwoToOneCRHScheme>::evaluate(
                &param,
                &Fr::from(1),
                &Fr::from(0),
            )?;

        println!("{result}");

        assert_eq!(
            result,
            Fr::from_str(
                "21581643069407877618298966131175370729897531221281133974758693417099906058024"
            )
            .unwrap()
        );

        Ok(())
    }
}
