use std::marker::PhantomData;

use ark_ff::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod params;
pub mod utils;

#[cfg(feature = "paramgen")]
pub mod paramgen;

pub use traits::*;
mod traits;

pub trait MiMCParameters: Clone + Default {
    const ROUNDS: usize;
    const EXPONENT: usize;
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
    /// MiMC 2n/n x^exp permute
    pub fn permute_feistel(&self, state: Vec<F>) -> Vec<F> {
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
            let mut tn = F::one();
            (0..P::EXPONENT).for_each(|_| tn *= t);
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (x_r + tn, x_l),
                false => (x_l, x_r + tn),
            };
        }
        (x_l, x_r)
    }

    /// MiMC n/n x^exp permute
    pub fn permute_non_feistel(&self, state: Vec<F>) -> Vec<F> {
        let mut r = self.k;
        for s in state.into_iter() {
            r += s + self.non_feistel(s, r);
        }
        let mut outputs = vec![r];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    r += self.non_feistel(r, r);
                    outputs.push(r);
                }
                outputs
            }
        }
    }

    fn non_feistel(&self, x: F, k: F) -> F {
        let mut r = F::zero();
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => k + x,
                false => k + r + self.round_keys[i],
            };
            let mut tn = F::one();
            (0..P::EXPONENT).for_each(|_| tn *= t);
            r = tn;
        }
        r + k
    }
}
