use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRHGadget, CRHGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};

use crate::{
    utils::to_field_elements_r1cs, MiMC, MiMCFeistelCRH, MiMCNonFeistelCRH, MiMCParameters,
};

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

impl<F: PrimeField, P: MiMCParameters> EqGadget<F> for MiMCVar<F, P> {
    fn is_eq(
        &self,
        other: &Self,
    ) -> Result<ark_r1cs_std::prelude::Boolean<F>, ark_relations::r1cs::SynthesisError> {
        self.k
            .is_eq(&other.k)?
            .and(&self.round_keys.is_eq(&other.round_keys)?)
    }
}

impl<F: PrimeField, P: MiMCParameters> CRHGadget<MiMCFeistelCRH<F, P>, F>
    for MiMCFeistelCRHGadget<F, P>
{
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;
        Ok(parameters.permute_feistel(fields)[0].clone())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHGadget<MiMCFeistelCRH<F, P>, F>
    for MiMCFeistelCRHGadget<F, P>
{
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[ark_r1cs_std::uint8::UInt8<F>],
        right_input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        assert_eq!(left_input.len(), right_input.len());
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .cloned()
            .collect();

        <Self as CRHGadget<_, _>>::evaluate(parameters, &chained)
    }
}

impl<F: PrimeField, P: MiMCParameters> CRHGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHGadget<F, P>
{
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;
        Ok(parameters.permute_non_feistel(fields)[0].clone())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHGadget<F, P>
{
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[ark_r1cs_std::uint8::UInt8<F>],
        right_input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        assert_eq!(left_input.len(), right_input.len());
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .cloned()
            .collect();

        <Self as CRHGadget<_, _>>::evaluate(parameters, &chained)
    }
}
