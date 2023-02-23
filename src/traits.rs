use std::marker::PhantomData;

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::PrimeField;

use crate::{MiMC, MiMCParameters};

#[derive(Debug, Default, Clone, Copy)]
pub struct MiMCFeistelCRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

#[derive(Debug, Default, Clone, Copy)]
pub struct MiMCNonFeistelCRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> CRHScheme for MiMCFeistelCRH<F, P> {
    type Input = [F];

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

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(parameters.permute_feistel(input.borrow())[0])
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHScheme for MiMCFeistelCRH<F, P> {
    type Input = F;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as CRHScheme>::setup(r)
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(parameters.permute_feistel(&[*left_input.borrow(), *right_input.borrow()])[0])
    }

    fn compress<T: std::borrow::Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}

impl<F: PrimeField, P: MiMCParameters> CRHScheme for MiMCNonFeistelCRH<F, P> {
    type Input = [F];

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

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(parameters.permute_non_feistel(input.borrow())[0])
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHScheme for MiMCNonFeistelCRH<F, P> {
    type Input = F;

    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as CRHScheme>::setup(r)
    }

    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Ok(parameters.permute_non_feistel(&[*left_input.borrow(), *right_input.borrow()])[0])
    }

    fn compress<T: std::borrow::Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}
