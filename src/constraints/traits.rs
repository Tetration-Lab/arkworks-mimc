use std::marker::PhantomData;

use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};

use crate::{MiMC, MiMCFeistelCRH, MiMCNonFeistelCRH, MiMCParameters};

use super::MiMCVar;

#[derive(Debug, Clone, Copy, Default)]
pub struct MiMCFeistelCRHGadget<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

#[derive(Debug, Clone, Copy, Default)]
pub struct MiMCNonFeistelCRHGadget<F: PrimeField, P: MiMCParameters>(
    PhantomData<F>,
    PhantomData<P>,
);

impl<F: PrimeField, P: MiMCParameters> AllocVar<MiMC<F, P>, F> for MiMCVar<F, P> {
    fn new_variable<T: std::borrow::Borrow<MiMC<F, P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let mimc = f()?.borrow().clone();
        let cs = cs.into().cs();
        Ok(Self {
            num_outputs: mimc.num_outputs,
            params: PhantomData,
            k: FpVar::new_variable(cs.clone(), || Ok(mimc.k), mode)?,
            round_keys: mimc
                .round_keys
                .into_iter()
                .map(|e| -> Result<_, _> { FpVar::new_variable(cs.clone(), || Ok(e), mode) })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl<F: PrimeField, P: MiMCParameters> CRHSchemeGadget<MiMCFeistelCRH<F, P>, F>
    for MiMCFeistelCRHGadget<F, P>
{
    type InputVar = [FpVar<F>];

    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(parameters
            .permute_feistel(input)
            .into_iter()
            .next()
            .unwrap())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHSchemeGadget<MiMCFeistelCRH<F, P>, F>
    for MiMCFeistelCRHGadget<F, P>
{
    type InputVar = FpVar<F>;

    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(parameters
            .permute_feistel(&[left_input, right_input])
            .into_iter()
            .next()
            .unwrap())
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        <Self as TwoToOneCRHSchemeGadget<_, _>>::evaluate(parameters, left_input, right_input)
    }
}

impl<F: PrimeField, P: MiMCParameters> CRHSchemeGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHGadget<F, P>
{
    type InputVar = [FpVar<F>];

    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(parameters
            .permute_non_feistel(input)
            .into_iter()
            .next()
            .unwrap())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHSchemeGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHGadget<F, P>
{
    type InputVar = FpVar<F>;

    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(parameters
            .permute_non_feistel(&[left_input, right_input])
            .into_iter()
            .next()
            .unwrap())
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        <Self as TwoToOneCRHSchemeGadget<_, _>>::evaluate(parameters, left_input, right_input)
    }
}
