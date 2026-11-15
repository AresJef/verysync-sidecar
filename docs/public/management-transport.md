# Management TLS and explicit proxies (unreleased)

`ManagementTransport` selects trust and proxy policy for one management
connection. Pass it to `ConnectOptions::transport()` or
`GuiLoginOptions::transport()`. The default retains normal TLS certificate and
hostname verification and uses no proxy. Ambient proxy variables and PAC are
not consulted. No operating-system trust store or global environment is changed.

```no_run
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, ManagementEndpoint,
    ManagementProxy, ManagementTransport,
};

# async fn connect(
#   endpoint: ManagementEndpoint, expected: DeviceId, key: ApiKey,
#   ca_pem: &[u8], proxy_url: &str, proxy_user: &str, proxy_password: &str
# ) -> verysync_sidecar::Result<Client> {
let transport = ManagementTransport::default()
    .trusted_certificates_pem(ca_pem)?
    .proxy(ManagementProxy::new(proxy_url)?.basic_auth(proxy_user, proxy_password)?);
let client = Client::connect(
    ConnectOptions::new(endpoint, key)
        .expected_device_id(expected)
        .transport(transport),
).await?;
# Ok(client)
# }
```

`trusted_certificates_pem()` adds the certificates in a PEM bundle to the normal
platform roots. `trusted_certificate_der()` adds one DER certificate. Each input
is nonempty and at most one MiB; a PEM bundle must contain certificates, and a
transport accepts at most 64 additional roots across calls. PEM decoding is not
full X.509 validation: malformed DER can fail when the HTTP client constructs its
trust store. Successful decoding also does not prove a server's certificate,
name, validity interval or actual handshake will be accepted. The methods do
not disable certificate or hostname verification and do not pin a leaf public
key. Treat added roots as trust anchors for this connection, including an HTTPS
proxy when selected. Both methods require the `tls` feature.

`ManagementProxy::new()` accepts an explicit HTTP or HTTPS proxy authority. It
rejects URL user information, path prefixes, queries, fragments, controls and
port zero. Proxy Basic credentials are supplied separately, at most 4096 bytes
each with no controls; a username cannot contain a colon. Debug omits the proxy
address and credentials. HTTP targets use proxy forwarding; HTTPS targets use
CONNECT. An HTTPS proxy additionally encrypts the proxy hop and requires `tls`.
An HTTP proxy sends its Basic credential without encryption on that hop; HTTP
targets also expose target traffic to the proxy. Select the transport appropriate
for the actual network. Proxy failure does not fall back to a direct connection.

Proxy authentication is distinct from the target API key and native GUI
credentials. The library does not put proxy credentials in target URLs or the
target Authorization header. Ordinary version errors and Client Debug omit
free-form version text received through a credentialed proxy, since a proxy can
reflect even encoded credentials. Explicit returned metadata and response-body
accessors remain private caller-controlled data and must be handled accordingly.

The selected policy is retained by `Client::reconnect_with_api_key()`, credential
rotation and same-endpoint GUI reload reconciliation. Cloned clients and GUI
sessions retain their constructed transport. Additional certificates are supplied as bytes; this API does not open a
caller-selected certificate-file path. Normal platform root loading remains
part of the TLS backend. Managed default Unix
sockets remain distinct: combining a Unix management endpoint with TCP proxy or
additional TLS roots returns a configuration error before making a request.

The controlled runtime case uses an ephemeral CA, a TLS reverse proxy forwarding
only to an isolated official v2.33.2 core, and two private authenticated proxies.
It verifies actual authenticated reads and folder registration/removal, retained
file bytes, PEM and DER trust, untrusted-chain and wrong-hostname refusal,
HTTP/HTTPS proxy routing, refusal of wrong proxy credentials, retained reconnect
policy, native GUI login/logout and absence of proxy authentication at the TLS
origin. This is real SDK TLS transport to a controlled reverse proxy and native
core backend. Direct native GUI TLS listener changes and the full same-source
platform matrix have their own acceptance gates. No remote public service or
user trust-store modification is needed for this test.

The test-only peer binds literal loopback addresses without reverse DNS. Its
original 12-second readiness deadline is unchanged. If startup times out, the
test reports a bounded, fixed-name startup phase and child-exit status; private
stderr stays in the dedicated test directory. This diagnostic does not establish
that a platform's full runtime acceptance has passed.

The implementation uses the locked reqwest transport APIs for
[additional roots](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html#method.tls_certs_merge),
[certificate decoding](https://docs.rs/reqwest/0.13.5/reqwest/tls/struct.Certificate.html)
and [explicit proxy routing](https://docs.rs/reqwest/0.13.5/reqwest/struct.Proxy.html).
