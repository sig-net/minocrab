//! Proving, in process.
//!
//! No proof server, no child process, and no network once the KZG parameters
//! are on disk. That is notes/mpc-publisher.org §2's claim about the port,
//! and [`InProcessProver`] is the whole of what it costs: a `ProvingProvider`
//! that resolves key material off the managed directory and hands the
//! preimage to `ProofPreimage::prove::<zkir_v3::IrSource>`.
//!
//! # Why it is written here rather than imported
//!
//! `midnight_ledger::test_utilities::CombinedProofProvider` is the upstream
//! one, and it is unreachable twice over: it is a private struct behind the
//! ledger's `test-utilities` + `proving` features, and its resolver
//! (`ledger::prove::Resolver`) insists on a `ZswapResolver`, whose parameter
//! sets a respond transaction has no use for — it carries no shielded offer.
//! `zkir::LocalProvingProvider`, the public one, is the ZKIR **v2** crate's
//! and will not load our `ir-source[v3-generic]`. So this is a MECHANICAL
//! TRANSLATION of `CombinedProofProvider`'s v3 arm
//! (`ledger/src/test_utilities.rs:749-818`), the same one
//! `minocrab-contracts`' `tests/signet_real_proof.rs` made for M29 E.
//!
//! # The dust half of the resolver
//!
//! [`SignerResolver`] tries the managed directory first and the ledger's own
//! [`DustResolver`] second. The dust half resolves exactly one key —
//! `midnight/dust/spend` — and it is dead weight until M30 rung C puts a
//! dust spend in the transaction; it is wired now because the fee proof is
//! the one other proof a published respond transaction will contain, and a
//! resolver that cannot find its key fails at proving time, deep inside an
//! `anyhow::Error`, rather than at construction.

use std::io;

use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_base_crypto::rng::SplittableRng;
use midnight_ledger::dust::{DustResolver, DUST_EXPECTED_FILES};
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{
    KeyLocation, ParamsProverProvider, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider,
    Resolver, Zkir,
};
use midnight_zkir_v3::IrSource;
use rand::{CryptoRng, Rng};

use crate::error::PublishError;
use crate::keys::ManagedDir;

/// The KZG parameter provider, in the mode a publisher wants: served from the
/// on-disk cache (`$MIDNIGHT_PP`, `$XDG_CACHE_HOME/midnight/zk-params`,
/// `~/.cache/midnight/zk-params`), fetching only what is missing.
///
/// `FetchMode::OnDemand` will reach `srs.midnight.network` for a parameter set
/// that is NOT cached. Ship the params in the image — the whole point of
/// notes/mpc-publisher.org §2's "no network touch" — and it never does.
pub fn params_provider() -> Result<MidnightDataProvider, PublishError> {
    MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![]).map_err(|e| {
        PublishError::Io { path: "the KZG parameter cache".to_string(), source: e }
    })
}

/// The ledger's own dust-key provider, over the same cache.
pub fn dust_resolver() -> Result<DustResolver, PublishError> {
    let provider =
        MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, DUST_EXPECTED_FILES.to_vec())
            .map_err(|e| PublishError::Io {
                path: "the dust key cache".to_string(),
                source: e,
            })?;
    Ok(DustResolver(provider))
}

/// Our circuits' keys, then the dust spend's.
pub struct SignerResolver {
    pub managed: ManagedDir,
    /// `None` while nothing in the transaction spends dust — see the module
    /// header, and M30 rung C.
    pub dust: Option<DustResolver>,
}

impl SignerResolver {
    pub fn new(managed: ManagedDir) -> SignerResolver {
        SignerResolver { managed, dust: None }
    }

    /// The same resolver with the ledger's dust keys behind it.
    pub fn with_dust(managed: ManagedDir) -> Result<SignerResolver, PublishError> {
        Ok(SignerResolver { managed, dust: Some(dust_resolver()?) })
    }
}

impl Resolver for SignerResolver {
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        if let Some(material) = self.managed.resolve_key(key.clone()).await? {
            return Ok(Some(material));
        }
        match &self.dust {
            Some(dust) => dust.resolve_key(key).await,
            None => Ok(None),
        }
    }
}

/// The in-process proving provider: [`SignerResolver`] for key material,
/// `MidnightDataProvider` for the KZG parameters, `zkir_v3::IrSource` for the
/// circuit.
pub struct InProcessProver<'a, R: Rng + CryptoRng + SplittableRng> {
    pub rng: R,
    pub resolver: &'a SignerResolver,
    pub params: &'a MidnightDataProvider,
}

impl<R: Rng + CryptoRng + SplittableRng> ProvingProvider for InProcessProver<'_, R> {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        let material = self
            .resolver
            .resolve_key(preimage.key_location.clone())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no key material for '{}'", preimage.key_location.0))?;
        let ir = IrSource::load_ir_from_tagged(io::Cursor::new(&material.ir_source[..]))?;
        preimage.check(&ir)
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let mut preimage = preimage.clone();
        if let Some(binding_input) = overwrite_binding_input {
            preimage.binding_input = binding_input;
        }
        preimage
            .prove::<IrSource>(self.rng, self.params, self.resolver)
            .await
            .map(|(proof, _)| proof)
    }

    fn split(&mut self) -> Self {
        InProcessProver { rng: self.rng.split(), resolver: self.resolver, params: self.params }
    }

    fn resolver(&self) -> &impl Resolver {
        self.resolver
    }
}

/// The KZG parameter provider is also what proving asks for its parameters;
/// spelled out so a caller can pre-warm a `k` outside a timed section, the way
/// `crates/minocrab-bench` does.
pub async fn warm_params(params: &MidnightDataProvider, k: u8) -> Result<(), PublishError> {
    params.get_params(k).await.map(|_| ()).map_err(|e| PublishError::Io {
        path: format!("KZG parameters for k={k}"),
        source: e,
    })
}
