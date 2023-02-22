use std::marker::PhantomData;

use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_ff::{FpParameters, PrimeField};

use crate::{utils::to_field_elements, MiMC, MiMCParameters};

#[derive(Debug, Default, Clone, Copy)]
pub struct MiMCFeistelCRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRH for MiMCFeistelCRH<F, P> {
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
        Ok(parameters.permute_feistel(fields)[0])
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRH for MiMCFeistelCRH<F, P> {
    const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS;

    const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as CRH>::setup(r)
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
        <Self as CRH>::evaluate(parameters, &chained)
    }
}
