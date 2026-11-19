
## Exact ignore patterns and default restoration

`ignore_patterns` reads the selected folder's actual file lines, expanded engine
patterns and parser diagnostic. It preserves null file lines separately from an
empty array. Missing schema fields and HTTP failures remain errors. A stored
invalid file remains observable with `parse_error`; a GET does not silently
replace its rules or turn parsing failure into an empty successful snapshot.

`IgnorePatterns::new` retains exact ordered lines, including blank lines,
comments, escape directives, negation and pattern separators. These are engine
patterns, not host filesystem paths; they are never converted with the caller's
path rules. SDK input bounds allow at most 4096 lines and 256 KiB of UTF-8 text,
without embedded CR, LF or NUL. The engine interprets glob and include syntax;
the SDK does not guess equivalent patterns or expand included files itself.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::IgnorePatterns;
let rules = IgnorePatterns::new(vec![
    "// Keep one temporary file".into(), "!keep.tmp".into(), "*.tmp".into(),
])?;
let changed = client.set_ignore_patterns(folder, &rules).await?;
let defaults = client.reset_ignore_patterns(folder).await?;
# let _ = (changed, defaults);
# Ok(()) }
```

`set_ignore_patterns` replaces the whole selected ignore file once, then reads
actual state and reports exact ordered equality through
`requested_patterns_match`. An empty input explicitly removes all patterns.
The fixed engine returns null file lines and an empty expansion for that case.
`reset_ignore_patterns` instead restores the engine's built-in defaults; those
defaults include temporary-file exclusions. The library embeds no vendor list.
Changing rules can expose previously ignored files to synchronization. The
methods do not issue a local file-delete command or certify peer completion.
Observe actual indexing separately and coordinate independent writers.

The engine can store invalid rules and return HTTP 200 with a nonempty parser
error. A modifying method reports `Error::IgnorePatternsRejected`, retaining
the returned `IgnoreSnapshot` for explicit inspection. This is not a successful
rule change and does not imply rollback. Read current state, then explicitly
replace or reset it. Transport, malformed-response or failed-readback outcomes
after a possible write remain `MutationOutcomeUnknown`; no write is retried.
Every mutation uses a fresh identity/existence preflight and the shared Client
clone lock. Separate requests and external writers are not one transaction.
Debug output omits file lines, expanded rules, parser text and unknown metadata.

Native tests check the default temporary-file exclusion, explicit empty rules,
ordered negation and a subdirectory pattern, restart persistence, actual stored
invalid syntax and recovery using real default restoration. Indexed counts
change independently of configuration acknowledgements; another folder's rules
and index plus every synthetic file's bytes remain unchanged. Normal exit of
the owned process tree is also required.

Global default templates have their own native GET/PUT interface:

```rust,no_run
# async fn defaults(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::IgnorePatterns;
let rules = IgnorePatterns::new(vec!["*.temporary".into()])?;
let stored = client.set_default_ignore_patterns(&rules).await?;
assert!(stored.requested_fields_match);
let template = client.default_ignore_patterns().await?;
// Explicitly choose a folder and apply these rules to its actual ignore file.
let selected = IgnorePatterns::new(template.lines)?;
let applied = client.set_ignore_patterns(folder, &selected).await?;
assert!(applied.requested_patterns_match);
# Ok(()) }
```

`IgnoreDefaults` preserves ordered lines and unknown native fields. A replacement
holds the shared clone lock, authenticates the current identity, reads the actual
template, sends one complete PUT retaining unknown values, and compares the full
typed readback. Independent writers are not one transaction. A failed readback
after a possible write is `MutationOutcomeUnknown`; no write is retried.
`ConfigurationSnapshot::default_ignore_patterns` and
`set_default_ignore_patterns` also support an explicit complete configuration
save. Empty lines clear the template without rewriting existing ignore files.

Saving a template does not establish parsing or automatic folder inheritance.
On the six tested native v2.33.2 macOS, Windows and Linux AMD64/ARM64 profiles,
the core stores and persists it, including invalid include syntax, but folders
newly registered through `Client::create_folder` still use the vendor's rules.
Other targets and final integrated acceptance retain their separate gates. Select an
existing folder and call `set_ignore_patterns` explicitly when applying the
stored lines; inspect its parser result and actual indexing separately. Native
tests retain existing ignore-file bytes, synthetic data and identity, demonstrate
real index exclusion after explicit application, and require normal restart
persistence and owned-tree exit.
