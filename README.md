# Arkworks MiMC

[Arkworks](https://github.com/arkworks-rs/) implementation of cryptographic hash function MiMC [[AGR+16]](https://eprint.iacr.org/2016/492.pdf) on $n/n$ non-feistel and $2n/n$ feistel block cipher with variable round keys and exponentiation.

R1CS gadgets and CRH gadget traits are available under `r1cs` crate feature.

## Supported Field Parameters

We provide pre-generated round keys for some selected prime fields which available in [circomlibjs](https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js) package.

### Feistel ($2n/n$)

- 220 rounds with $x^5$ on BN254
- 220 rounds with $x^5$ on BLS12-381

### Non-Feistel ($n/n$)

- 91 rounds with $x^7$ on BN254
- 91 rounds with $x^7$ on BLS12-381

## Usage

### Custom Rounds And Exponent

```rust
// Create new struct to use as MiMC param
#[derive(Clone, Default)]
struct MyMiMCParams;

// Implement `MiMCParameters` for that struct
impl MiMCParameters for MyMiMCParams {
    const ROUNDS: usize = 220; // Customizable
    const EXPONENT: usize = 3; // Customizable
}

// Randomize MiMC key and round keys
let mimc = <MiMCFeistelCRH<Fr, MyMiMCParams> as CRHTrait>::setup(rng)?;
// Or initialize with customized key/round keys/outputs
let custom_mimc = MiMC::new(1, Fr::from(1), mimc.round_keys.clone());

// Use MiMC directly,
// Non-Feistel
let _ = mimc.permute_non_feistel(vec![Fr::from(1), Fr::from(0)])
// Feistel
let _ = mimc.permute_feistel(vec![Fr::from(1), Fr::from(0)]);

// Or use MiMC through arkworks's crypto-primitive traits
// CRH
let _ = <MiMCNonFeistelCRH<_, _> as CRH>::evaluate(
    &mimc,
    &to_bytes!(Fr::from(1))?
)?;
// CRH
let _ = <MiMCFeistelCRH<_, _> as TwoToOneCRH>::evaluate(
    &mimc,
    &to_bytes!(Fr::from(1))?
)?;
```

### Pre-Generated Rounds

Enable specific feature containing parameter that will be used.

In `cargo.toml`

```yaml
arkworks-mimc = { ..., features = ["mimc_91_bn254"] }
```

In `.rs`

```rust
let mimc = MiMC::<Fr, MIMC_91_BN254_PARAMS>::new(
    1,
    Fr::zero(),
    round_keys_contants_to_vec(&MIMC_91_BN254_ROUND_KEYS),
);
```
