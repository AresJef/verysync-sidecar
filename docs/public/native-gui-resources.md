# Native GUI resources

The native program exposes a few resources useful independently of its GUI.
These methods reuse the explicit authenticated management connection, selected
URL prefix, response bound and deadline. They execute no browser or JavaScript.

- `native_preferred_languages(header)` sends one explicit `Accept-Language`
  header to the native preference helper. It returns the native ordered strings,
  including its `['']` result for an empty header. The fixed program lowercases
  tags and orders the tested weighted preferences. This negotiates that request;
  it does not change the GUI's selected language, which its current browser code
  stores in local browser preferences.
- `native_gui_metadata()` reads `meta.js`, parses the fixed
  `var metadata = <JSON>;` assignment without executing it, and checks the
  certificate identity and short display identity. Authentication flags and
  private future fields remain available explicitly. Unexpected script wrappers,
  trailing executable text, malformed data or mismatched identity are errors.
- `native_qr_code(text)` asks the engine to encode explicit text as PNG through
  `qr/?text=...`. It retains the real trailing URL separator and encodes text
  exactly once. The SDK checks the declared PNG media type, signature and IHDR,
  then returns private bytes and pixel dimensions. It does not decode, save,
  render, open or register the result. Native QR capacity errors are retained;
  the SDK's 4096-byte input bound is not a promise of that encoding capacity.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let preferences = client.native_preferred_languages("en;q=0.2, fr-FR;q=0.9").await?;
let metadata = client.native_gui_metadata().await?;
let qr = client.native_qr_code("explicit synthetic text").await?;
let png = qr.png_bytes();
# let _ = (preferences, metadata, png);
# Ok(()) }
```

QR text can contain sharing credentials. Ordinary Debug output omits image bytes
and metadata identities/extra fields. Returned resource data remains untrusted;
apply appropriate checks when passing it to another renderer or application.
Root resources are distinct from `rest/` routes and from browser-local settings.
Static GUI assets can be read through the explicitly scoped raw request API;
the library does not rebuild, evaluate, configure or serve a second GUI.

The native test checks two deterministic v2.33.2 QR reference vectors, including
special characters and Chinese text. Their returned PNGs were independently
decoded using Apple Vision to the exact requested texts. Cross-platform tests
compare the native bytes with those independently decoded references, rather
than accepting only an image header or HTTP success. A changed PNG encoding
requires independent revalidation before updating a reference. This is encoded
content evidence, not a QR-reader or image-renderer implementation in the SDK.
