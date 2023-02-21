use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRHGadget, CRHGadget as CRHGadgetTrait};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, FieldVar},
};
use ark_std::vec::Vec;

use crate::{utils::to_field_elements_r1cs, MiMC, MiMCParameters, CRH};

#[derive(Debug, Clone)]
pub struct MiMCVar<F: PrimeField, P: MiMCParameters> {
    params: PhantomData<P>,
    k: FpVar<F>,
    round_keys: Vec<FpVar<F>>,
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    pub fn new(k: FpVar<F>, round_keys: Vec<FpVar<F>>) -> Self {
        Self {
            params: PhantomData,
            k,
            round_keys,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    fn permute(&self, state: Vec<FpVar<F>>) -> FpVar<F> {
        assert!(state.len() == P::WIDTH, "Invalid state length");
        let mut r = FpVar::<F>::zero();
        let mut c = FpVar::<F>::zero();
        for s in state.into_iter() {
            r = r + s;
            (r, c) = self.feistel(r, c);
        }
        r
    }

    fn feistel(&self, left: FpVar<F>, right: FpVar<F>) -> (FpVar<F>, FpVar<F>) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => &self.k + &x_l,
                false => &self.k + &x_l + &self.round_keys[i - 1],
            };
            let t2 = &t * &t;
            let t4 = &t2 * &t2;
            let t5 = &t4 * &t;
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (&x_r + &t5, x_l),
                false => (x_l, &x_r + &t5),
            };
        }
        (x_l, x_r)
    }
}

impl<F: PrimeField, P: MiMCParameters> AllocVar<MiMC<F, P>, F> for MiMCVar<F, P> {
    fn new_variable<T: std::borrow::Borrow<MiMC<F, P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let mimc = f()?.borrow().clone();
        let cs = cs.into().cs();
        Ok(Self {
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

#[derive(Debug, Clone, Copy)]
pub struct CRHGadget<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRHGadgetTrait<CRH<F, P>, F> for CRHGadget<F, P> {
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;

        assert!(
            fields.len() <= P::WIDTH,
            "Invalid input length for width paramete"
        );
        Ok(parameters.permute(fields))
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHGadget<CRH<F, P>, F> for CRHGadget<F, P> {
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

        <Self as CRHGadgetTrait<CRH<F, P>, F>>::evaluate(parameters, &chained)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn constraints() {}
}
