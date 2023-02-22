use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRHGadget, CRHGadget as CRHGadgetTrait};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, FieldVar},
};
use ark_std::vec::Vec;

use crate::{traits::MiMCFeistelCRH, utils::to_field_elements_r1cs, MiMC, MiMCParameters};

#[derive(Debug, Clone)]
pub struct MiMCVar<F: PrimeField, P: MiMCParameters> {
    num_outputs: usize,
    params: PhantomData<P>,
    k: FpVar<F>,
    round_keys: Vec<FpVar<F>>,
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    pub fn new(num_outputs: usize, k: FpVar<F>, round_keys: Vec<FpVar<F>>) -> Self {
        assert_eq!(round_keys.len(), P::ROUNDS, "Invalid round keys length");
        Self {
            num_outputs,
            params: PhantomData,
            k,
            round_keys,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    fn permute(&self, state: Vec<FpVar<F>>) -> Vec<FpVar<F>> {
        let mut r = FpVar::zero();
        let mut c = FpVar::zero();
        for s in state.into_iter() {
            r = &r + &s;
            (r, c) = self.feistel(r, c);
        }
        let mut outputs = vec![r.clone()];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    (r, c) = self.feistel(r.clone(), c);
                    outputs.push(r.clone());
                }
                outputs
            }
        }
    }

    fn feistel(&self, left: FpVar<F>, right: FpVar<F>) -> (FpVar<F>, FpVar<F>) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => &self.k + &x_l,
                false => &self.k + &x_l + &self.round_keys[i],
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

#[derive(Debug, Clone, Copy)]
pub struct CRHGadget<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRHGadgetTrait<MiMCFeistelCRH<F, P>, F> for CRHGadget<F, P> {
    type OutputVar = FpVar<F>;

    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;
        Ok(parameters.permute(fields)[0].clone())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHGadget<MiMCFeistelCRH<F, P>, F>
    for CRHGadget<F, P>
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

        <Self as CRHGadgetTrait<MiMCFeistelCRH<F, P>, F>>::evaluate(parameters, &chained)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{TwoToOneCRH, TwoToOneCRHGadget},
        CRH as CRHTrait,
    };
    use ark_ff::to_bytes;
    use ark_r1cs_std::{
        fields::fp::FpVar,
        prelude::{AllocVar, EqGadget, FieldVar},
        R1CSVar, ToBytesGadget,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use crate::{MiMCFeistelCRH, MiMCParameters};

    use super::{CRHGadget, MiMCVar};

    #[derive(Clone, Default)]
    struct MiMCMock;

    impl MiMCParameters for MiMCMock {
        const ROUNDS: usize = 5;
        const EXPONENT: usize = 5;
    }

    #[test]
    fn constraints() -> Result<(), Box<dyn Error>> {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mimc = <MiMCFeistelCRH<Fr, MiMCMock> as CRHTrait>::setup(rng)?;

        let x_l = Fr::from(20);
        let x_r = Fr::from(200);
        let hashed = <MiMCFeistelCRH<Fr, MiMCMock> as TwoToOneCRH>::evaluate(
            &mimc,
            &to_bytes!(x_l)?,
            &to_bytes!(x_r)?,
        )?;

        let x_l_var = FpVar::new_witness(cs.clone(), || Ok(x_l))?;
        let x_r_var = FpVar::new_witness(cs.clone(), || Ok(x_r))?;
        let k_var = FpVar::new_input(cs.clone(), || Ok(mimc.k))?;

        let round_keys = Vec::<FpVar<Fr>>::new_constant(cs, mimc.round_keys)?;
        let mimc_var = MiMCVar::<_, MiMCMock>::new(1, k_var, round_keys);
        let hashed_var =
            <CRHGadget<_, MiMCMock> as TwoToOneCRHGadget<MiMCFeistelCRH<_, _>, _>>::evaluate(
                &mimc_var,
                &x_l_var.to_bytes()?,
                &x_r_var.to_bytes()?,
            )?;

        assert!(FpVar::constant(hashed).is_eq(&hashed_var)?.value()?);

        Ok(())
    }
}
