use rdkafka::client::{ClientContext, OAuthToken};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::ConsumerContext;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tracing::debug;

use crate::config::ClusterConfig;
use crate::error::KlagError;

// ---------------------------------------------------------------------------
// Token provider abstraction
// ---------------------------------------------------------------------------

/// Generates an OAuth token on demand. Cloud-specific implementations (e.g.
/// MSK IAM, GCP, Azure) live in their own structs.
pub trait OAuthTokenProvider: Send + Sync {
    fn generate(&self) -> Result<OAuthToken, Box<dyn std::error::Error>>;
}

// ---------------------------------------------------------------------------
// AWS MSK IAM implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "msk-iam")]
use aws_types::region::Region;

/// Generates SigV4-presigned OAUTHBEARER tokens for Amazon MSK IAM.
#[cfg(feature = "msk-iam")]
pub struct MskIamTokenProvider {
    region: String,
    /// Tokio handle captured at construction. Used to drive the async signer
    /// from within the sync OAuth callback via a spawned OS thread.
    rt: Handle,
}

#[cfg(feature = "msk-iam")]
impl MskIamTokenProvider {
    /// Construct the provider, resolving the region if not explicitly supplied.
    ///
    /// Returns an error at construction time (i.e. at client startup) rather
    /// than silently producing a context that fails every token refresh.
    pub fn new(region: Option<String>, rt: Handle) -> Result<Self, String> {
        let resolved = match region {
            Some(r) => r,
            None => std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .map_err(|_| {
                    "MSK IAM auth requires an AWS region; set [clusters.aws_msk_iam] \
                     region = \"...\", or export AWS_REGION / AWS_DEFAULT_REGION"
                        .to_string()
                })?,
        };
        Ok(Self {
            region: resolved,
            rt,
        })
    }
}

#[cfg(feature = "msk-iam")]
impl OAuthTokenProvider for MskIamTokenProvider {
    fn generate(&self) -> Result<OAuthToken, Box<dyn std::error::Error>> {
        debug!(region = %self.region, "Generating MSK IAM OAuth token");

        let region = Region::new(self.region.clone());
        let rt = self.rt.clone();

        // The signer is async; this callback is sync. Spawning a new OS thread
        // lets rt.block_on run outside the tokio worker thread — the only safe
        // way to call block_on without nesting runtimes.
        //
        // The librdkafka poll/background thread stalls here for up to 10 s
        // while the token is fetched from AWS (~once every 15 min per client).
        // This is expected and matches the upstream crate example.
        let (token, expiry_ms) = std::thread::spawn(move || {
            rt.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    aws_msk_iam_sasl_signer::generate_auth_token(region),
                )
                .await
            })
        })
        .join()
        .map_err(|_| "MSK IAM OAuth token thread panicked")?
        .map_err(|_| "MSK IAM OAuth token request timed out after 10s")?
        .map_err(|e| format!("MSK IAM signer error: {e}"))?;

        Ok(OAuthToken {
            token,
            principal_name: String::new(),
            lifetime_ms: expiry_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared auth wiring
// ---------------------------------------------------------------------------

#[cfg(not(feature = "msk-iam"))]
const MSK_IAM_DISABLED_MSG: &str = "cluster has [clusters.aws_msk_iam] configured but this \
    binary was built without the `msk-iam` feature; rebuild with default features enabled \
    (cargo build --release) or pass --features msk-iam";

/// Build the shared OAuth token provider for a cluster, if MSK IAM is configured.
/// Call once per cluster and reuse the returned `Arc` for all librdkafka clients.
pub fn build_token_provider(
    config: &ClusterConfig,
) -> crate::error::Result<Option<Arc<dyn OAuthTokenProvider>>> {
    let Some(iam) = &config.aws_msk_iam else {
        return Ok(None);
    };

    #[cfg(feature = "msk-iam")]
    {
        let provider = MskIamTokenProvider::new(iam.region.clone(), Handle::current())
            .map_err(KlagError::Config)?;
        Ok(Some(Arc::new(provider)))
    }

    #[cfg(not(feature = "msk-iam"))]
    {
        let _ = iam;
        Err(KlagError::Config(MSK_IAM_DISABLED_MSG.to_string()))
    }
}

/// Inject MSK IAM SASL defaults before `consumer_properties` so explicit overrides win.
pub fn apply_msk_iam_sasl(config: &ClusterConfig, client_config: &mut ClientConfig) {
    if config.aws_msk_iam.is_some() {
        client_config.set("security.protocol", "SASL_SSL");
        client_config.set("sasl.mechanism", "OAUTHBEARER");
    }
}

// ---------------------------------------------------------------------------
// KlagContext — the single concrete ClientContext used everywhere
// ---------------------------------------------------------------------------

/// Custom librdkafka client context used for all client types. Drives the
/// OAUTHBEARER token-refresh callback through an [`OAuthTokenProvider`] when
/// one is configured, and is a zero-overhead pass-through otherwise.
///
/// Non-OAuth clusters pass `token_provider: None`; librdkafka never invokes
/// the callback because `sasl.mechanism=OAUTHBEARER` is only set on the client
/// config when `[clusters.aws_msk_iam]` is present. `ENABLE_REFRESH_OAUTH_TOKEN`
/// being `true` at the type level is therefore harmless for those clusters.
///
/// **OAUTHBEARER trade-off:** `ENABLE_REFRESH_OAUTH_TOKEN` is a compile-time
/// const, so this implementation takes over *any* `OAUTHBEARER` mechanism. If a
/// cluster sets `sasl.mechanism=OAUTHBEARER` via `consumer_properties` *without*
/// an `[clusters.aws_msk_iam]` block (e.g. for a generic OIDC provider), the
/// callback will return an error instead of using librdkafka's built-in OIDC
/// flow. All other mechanisms (SASL/PLAIN, SCRAM, SSL, Kerberos) are unaffected.
pub struct KlagContext {
    token_provider: Option<Arc<dyn OAuthTokenProvider>>,
}

impl KlagContext {
    pub fn new(token_provider: Option<Arc<dyn OAuthTokenProvider>>) -> Self {
        Self { token_provider }
    }
}

impl ClientContext for KlagContext {
    const ENABLE_REFRESH_OAUTH_TOKEN: bool = true;

    fn generate_oauth_token(
        &self,
        _oauthbearer_config: Option<&str>,
    ) -> Result<OAuthToken, Box<dyn std::error::Error>> {
        match &self.token_provider {
            Some(p) => p.generate(),
            None => Err(
                "OAUTHBEARER callback invoked but no token provider is configured \
                 for this cluster; add an [clusters.aws_msk_iam] block to the cluster config"
                    .into(),
            ),
        }
    }
}

/// Required so that `BaseConsumer<KlagContext>` compiles. All methods use
/// the default no-op implementations.
impl ConsumerContext for KlagContext {}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn test_handle() -> Handle {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .handle()
            .clone()
    }

    #[test]
    #[cfg(feature = "msk-iam")]
    fn msk_iam_provider_uses_explicit_region() {
        assert!(MskIamTokenProvider::new(Some("us-east-1".to_string()), test_handle()).is_ok());
    }

    #[test]
    #[cfg(feature = "msk-iam")]
    fn msk_iam_provider_falls_back_to_aws_region() {
        let _guard = EnvVarGuard::set("AWS_REGION", "eu-west-1");
        assert!(MskIamTokenProvider::new(None, test_handle()).is_ok());
    }

    #[test]
    #[cfg(feature = "msk-iam")]
    fn msk_iam_provider_falls_back_to_aws_default_region() {
        let _aws_region = EnvVarGuard::unset("AWS_REGION");
        let _guard = EnvVarGuard::set("AWS_DEFAULT_REGION", "ap-southeast-2");
        assert!(MskIamTokenProvider::new(None, test_handle()).is_ok());
    }

    #[test]
    #[cfg(feature = "msk-iam")]
    fn msk_iam_provider_errors_when_no_region_available() {
        let _aws_region = EnvVarGuard::unset("AWS_REGION");
        let _aws_default = EnvVarGuard::unset("AWS_DEFAULT_REGION");
        match MskIamTokenProvider::new(None, test_handle()) {
            Err(e) => assert!(e.contains("MSK IAM auth requires an AWS region")),
            Ok(_) => panic!("missing region should fail"),
        }
    }
}
