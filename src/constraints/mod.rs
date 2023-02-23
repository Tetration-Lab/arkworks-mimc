use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_std::vec::Vec;

use crate::MiMCParameters;

mod traits;
pub use traits::*;

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
    pub fn permute_feistel<T: Borrow<FpVar<F>>>(&self, state: &[T]) -> Vec<FpVar<F>> {
        let mut r = FpVar::zero();
        let mut c = FpVar::zero();
        for s in state.iter() {
            r = &r + s.borrow();
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
            let mut tn = FpVar::one();
            (0..P::EXPONENT).for_each(|_| tn = &tn * &t);
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (&x_r + &tn, x_l),
                false => (x_l, &x_r + &tn),
            };
        }
        (x_l, x_r)
    }

    pub fn permute_non_feistel<T: Borrow<FpVar<F>>>(&self, state: &[T]) -> Vec<FpVar<F>> {
        let mut r = self.k.clone();
        for s in state.iter() {
            r = &r + s.borrow() + &self.non_feistel(s.borrow(), &r);
        }
        let mut outputs = vec![r.clone()];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    r = &r + &self.non_feistel(&r, &r);
                    outputs.push(r.clone());
                }
                outputs
            }
        }
    }

    fn non_feistel(&self, x: &FpVar<F>, k: &FpVar<F>) -> FpVar<F> {
        let mut r = FpVar::zero();
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => k + x,
                false => k + r + &self.round_keys[i],
            };
            let mut tn = FpVar::one();
            (0..P::EXPONENT).for_each(|_| tn = &tn * &t);
            r = tn;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
    use ark_r1cs_std::{
        fields::fp::FpVar,
        prelude::{AllocVar, EqGadget, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use crate::{constraints::MiMCFeistelCRHGadget, MiMCFeistelCRH, MiMCParameters};

    use super::MiMCVar;

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
        let mimc = <MiMCFeistelCRH<Fr, MiMCMock> as CRHScheme>::setup(rng)?;

        let x_l = Fr::from(20);
        let x_r = Fr::from(200);
        let hashed =
            <MiMCFeistelCRH<Fr, MiMCMock> as TwoToOneCRHScheme>::evaluate(&mimc, &x_l, &x_r)?;

        let x_l_var = FpVar::new_witness(cs.clone(), || Ok(x_l))?;
        let x_r_var = FpVar::new_witness(cs.clone(), || Ok(x_r))?;
        let k_var = FpVar::new_input(cs.clone(), || Ok(mimc.k))?;

        let round_keys = Vec::<FpVar<Fr>>::new_constant(cs, mimc.round_keys)?;
        let mimc_var = MiMCVar::<_, MiMCMock>::new(1, k_var, round_keys);
        let hashed_var = <MiMCFeistelCRHGadget<_, MiMCMock> as TwoToOneCRHSchemeGadget<
            MiMCFeistelCRH<_, _>,
            _,
        >>::evaluate(&mimc_var, &x_l_var, &x_r_var)?;

        assert!(FpVar::constant(hashed).is_eq(&hashed_var)?.value()?);

        Ok(())
    }
}
