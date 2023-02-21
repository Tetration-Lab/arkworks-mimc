use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRH, CRH as CRHTrait};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod params;

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
        assert!(state.len() == P::WIDTH, "Invalid state length");
        let mut l_out: F = F::zero();
        let mut r_out: F = F::zero();
        for (i, s) in state.iter().enumerate() {
            let (l, r) = match i == 0 {
                true => (*s, F::zero()),
                false => (l_out + s, r_out),
            };
            (l_out, r_out) = self.feistel(l, r);
        }

        l_out
    }

    fn feistel(&self, left: F, right: F) -> (F, F) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 || i == P::ROUNDS - 1 {
                true => self.k + x_l,
                false => self.k + x_l + &self.round_keys[i - 1],
            };
            let t2 = t * t;
            let t4 = t2 * t2;

            let temp_x_l = x_l;
            let temp_x_r = x_r;

            match i < P::ROUNDS - 1 {
                true => {
                    x_l = match i {
                        0 => temp_x_r,
                        _ => temp_x_r + (t4 * t),
                    };
                    x_r = temp_x_l;
                }
                false => {
                    x_r = temp_x_r + (t4 * t);
                    x_l = temp_x_l;
                }
            }
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
        let fields: Vec<F> = input.to_field_elements().unwrap_or_default();
        assert!(
            fields.len() <= P::WIDTH,
            "Invalid input length for width paramete"
        );
        let mut buffer = vec![F::zero(); P::WIDTH as usize];
        buffer.iter_mut().zip(fields).for_each(|(p, v)| *p = v);
        Ok(parameters.permute(buffer))
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
        Ok(Self::Parameters {
            params: PhantomData,
            k: F::rand(r),
            round_keys: (0..P::ROUNDS).map(|_| F::rand(r)).collect::<Vec<_>>(),
        })
    }

    fn evaluate(
        parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        assert_eq!(left_input.len(), right_input.len());
        assert!(left_input.len() * 8 <= Self::LEFT_INPUT_SIZE_BITS);
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .copied()
            .collect();

        <Self as CRHTrait>::evaluate(parameters, &chained)
    }
}
