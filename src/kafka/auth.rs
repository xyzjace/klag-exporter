use aws_config::Region;
use rdkafka::client::{ClientContext, OAuthToken};
use rdkafka::consumer::ConsumerContext;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tracing::debug;

// ---------------------------------------------------------------------------
// Token provider abstraction
// ---------------------------------------------------------------------------

/// Generates an OAuth token on demand. Cloud-specific implementations (e.g.
/// MSK IAM, GCP, Azure) live in their own structs
pub trait OAuthTokenProvider: Send + Sync {
    fn generate(&self) -> Result<OAuthToken, Box<dyn std::error::Error>>;
}

// ---------------------------------------------------------------------------
// AWS MSK IAM implementation
// ---------------------------------------------------------------------------

/// Generates SigV4-presigned OAUTHBEARER tokens for Amazon MSK IAM
pub struct MskIamTokenProvider {
    region: String,
    /// Tokio handle captured at construction. Used to drive the async signer
    /// from within the sync OAuth callback via a spawned OS thread.
    rt: Handle,
}

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
