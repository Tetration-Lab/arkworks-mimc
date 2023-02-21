use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRH, CRH as CRHTrait};
use ark_ff::{FpParameters, PrimeField};

use crate::utils::to_field_elements;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod params;
pub mod utils;

pub trait MiMCParameters: Clone + Default {
    const ROUNDS: usize;
}

#[derive(Debug, Default, Clone)]
pub struct MiMC<F: PrimeField, P: MiMCParameters> {
    num_outputs: usize,
    params: PhantomData<P>,
    k: F,
    round_keys: Vec<F>,
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    pub fn new(num_outputs: usize, k: F, round_keys: Vec<F>) -> Self {
        assert_eq!(round_keys.len(), P::ROUNDS, "Invalid round keys length");
        Self {
            num_outputs,
            params: PhantomData,
            k,
            round_keys,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    fn permute(&self, state: Vec<F>) -> Vec<F> {
        let mut r = F::zero();
        let mut c = F::zero();
        for s in state.into_iter() {
            r += s;
            (r, c) = self.feistel(r, c);
        }
        let mut outputs = vec![r];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    (r, c) = self.feistel(r, c);
                    outputs.push(r);
                }
                outputs
            }
        }
    }

    fn feistel(&self, left: F, right: F) -> (F, F) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => self.k + x_l,
                false => self.k + x_l + self.round_keys[i],
            };
            let t2 = t.square();
            let t4 = t2.square();
            let t5 = t4 * t;
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (x_r + t5, x_l),
                false => (x_l, x_r + t5),
            };
        }
        (x_l, x_r)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRHTrait for CRH<F, P> {
    const INPUT_SIZE_BITS: usize = <F::Params as FpParameters>::CAPACITY as usize;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(Self::Parameters {
            num_outputs: 1,
            params: PhantomData,
            k: F::rand(r),
            round_keys: (0..P::ROUNDS).map(|_| F::rand(r)).collect::<Vec<_>>(),
        })
    }

    fn evaluate(
        parameters: &Self::Parameters,
        input: &[u8],
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let fields: Vec<F> = to_field_elements(input);
        Ok(parameters.permute(fields)[0])
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRH for CRH<F, P> {
    const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS;

    const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as CRHTrait>::setup(r)
    }

    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        assert_eq!(left_input.len(), right_input.len());
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .copied()
            .collect();
        <Self as CRHTrait>::evaluate(parameters, &chained)
    }
}
