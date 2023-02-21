use ark_ff::{FpParameters, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::Boolean, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;
use ark_std::vec::Vec;

pub fn to_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let max_size = (<F::Params as FpParameters>::CAPACITY / 8) as usize;
    bytes
        .chunks(max_size + 1)
        .map(|chunk| F::from_le_bytes_mod_order(chunk))
        .collect::<Vec<_>>()
}

pub fn to_field_elements_r1cs<F: PrimeField>(
    bytes: &[UInt8<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let max_size = (<F::Params as FpParameters>::CAPACITY / 8) as usize;
    bytes
        .chunks(max_size + 1)
        .map(|chunk| Boolean::le_bits_to_fp_var(&chunk.to_bits_le()?))
        .collect::<Result<Vec<_>, _>>()
}
