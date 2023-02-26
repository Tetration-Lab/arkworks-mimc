use ark_ff::{FpParameters, PrimeField};
use rug::{Assign, Float};
use tiny_keccak::{Hasher, Keccak};

fn hash_keccak(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak::v256();
    let mut output = vec![0u8; 32];
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

fn round_keys_length<F: PrimeField>(permutation_type: PermutationType, exponent: usize) -> usize {
    let mut modulus = Float::new(20);
    modulus
        .assign(Float::parse_radix(<F::Params as FpParameters>::MODULUS.to_string(), 16).unwrap());
    let mut div = Float::new(20);
    div.assign(Float::parse(exponent.to_string()).unwrap());
    modulus.log10_mut();
    div.log10_mut();
    let len = (modulus / div).ceil().to_u32_saturating().unwrap() as usize;
    match permutation_type {
        PermutationType::Feistel => len * 2,
        PermutationType::NonFeistel => len,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum PermutationType {
    Feistel,
    #[default]
    NonFeistel,
}

#[inline]
pub fn generate_default_round_keys<F: PrimeField>(
    permutation_type: PermutationType,
    exponent: usize,
) -> (usize, Vec<F>) {
    generate_round_keys(
        permutation_type,
        exponent,
        match permutation_type {
            PermutationType::Feistel => b"mimcsponge",
            PermutationType::NonFeistel => b"mimc",
        },
    )
}

pub fn generate_round_keys<F: PrimeField>(
    permutation_type: PermutationType,
    exponent: usize,
    seed: &[u8],
) -> (usize, Vec<F>) {
    let round_keys_length = round_keys_length::<F>(permutation_type, exponent);
    let mut rounds: Vec<F> = vec![];
    let mut c = seed.to_vec();
    for _ in 0..round_keys_length {
        c = hash_keccak(&c);
        let f = F::from_be_bytes_mod_order(&c);
        rounds.push(f);
    }
    match permutation_type {
        PermutationType::Feistel => {
            rounds[round_keys_length - 1] = F::zero();
            rounds[0] = F::zero();
        }
        _ => {
            rounds[0] = F::zero();
        }
    };
    (round_keys_length, rounds)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_ff::Zero;

    use super::generate_default_round_keys;

    #[test]
    fn correct_keys() {
        let (length, rounds) =
            generate_default_round_keys::<Fr>(super::PermutationType::Feistel, 5);
        assert_eq!(length, 220);
        assert_eq!(rounds.last().unwrap(), &Fr::zero());
        assert_eq!(rounds.first().unwrap(), &Fr::zero());
        assert_eq!(
            rounds[length - 2],
            Fr::from_str(
                "2119542016932434047340813757208803962484943912710204325088879681995922344971"
            )
            .unwrap()
        );
    }
}
