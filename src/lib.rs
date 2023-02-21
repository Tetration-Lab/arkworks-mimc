use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRH, CRH as CRHTrait};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};

use crate::utils::to_field_elements;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod params;
pub mod utils;

pub trait MiMCParameters: Clone + Default {
    const ROUNDS: usize;
    const WIDTH: usize;
}

#[derive(Debug, Default, Clone)]
pub struct MiMC<F: PrimeField, P: MiMCParameters> {
    params: PhantomData<P>,
    k: F,
    round_keys: Vec<F>,
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    pub fn new(k: F, round_keys: Vec<F>) -> Self {
        Self {
            params: PhantomData,
            k,
            round_keys,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    fn permute(&self, state: Vec<F>) -> F {
        let mut r = F::zero();
        let mut c = F::zero();
        for s in state.into_iter() {
            r += s;
            (r, c) = self.feistel(r, c);
        }
        r
    }

    fn feistel(&self, left: F, right: F) -> (F, F) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => self.k + x_l,
                false => self.k + x_l + &self.round_keys[i],
            };
            let t2 = t.square();
            let t4 = t2.square();
            let t5 = t4 * t;
            //(x_l, x_r) = match i < P::ROUNDS - 1 {
            //true => (x_r + t5, x_l),
            //false => (x_l, x_r + t5),
            //};
            let tmp = x_r;
            match i < P::ROUNDS - 1 {
                true => {
                    x_r = x_l;
                    x_l = tmp + t5;
                }
                false => {
                    x_r = tmp + t5;
                }
            };
        }
        (x_l, x_r)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRHTrait for CRH<F, P> {
    const INPUT_SIZE_BITS: usize = <F::BigInt as BigInteger>::NUM_LIMBS * 8 * P::WIDTH as usize * 8;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(Self::Parameters {
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
        for i in &fields {
            println!("{i}");
        }
        assert!(
            fields.len() <= P::WIDTH,
            "Invalid input length for width parameter"
        );
        Ok(parameters.permute(fields))
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRH for CRH<F, P> {
    const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;

    const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;

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
        assert!(left_input.len() * 8 <= Self::LEFT_INPUT_SIZE_BITS);
        assert!(right_input.len() * 8 <= Self::RIGHT_INPUT_SIZE_BITS);
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .copied()
            .collect();
        <Self as CRHTrait>::evaluate(parameters, &chained)
    }
}
