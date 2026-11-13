
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
