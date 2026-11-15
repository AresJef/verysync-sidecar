# Native hardware observations

`native_cpu_hardware()`, `native_memory_hardware()`, `native_block_hardware()`
and `native_network_hardware()` read the connected program's hardware inventory.
They use the selected connection, identity checks, deadline and response bound.
They install no collector, change no device setting, send no report and perform
no controller filesystem inspection. The fixed core uses ghw v0.13.0; the
[upstream schemas](https://github.com/jaypipes/ghw/tree/v0.13.0/pkg) describe the
native field formats, while actual platform results require separate evidence.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let cpu = client.native_cpu_hardware().await?;
let block = client.native_block_hardware().await?;
for disk in block.disks.iter().flatten().flatten() {
    for partition in disk.partitions.iter().flatten().flatten() {
        let target_mount = partition.mount_point()?;
        // A target location is not a path to open on a remote controller.
        let _ = target_mount;
    }
}
# let _ = cpu;
# Ok(()) }
```

Counts, bytes, categories and link labels remain native observations. Block
totals are neither free-space estimates nor deduplicated physical capacity.
Memory's signed negative unknown values remain signed; null collections and
null records remain unknown. For example, the fixed macOS CPU backend can
report null entries within its core list. No missing record becomes a zeroed
core, empty successful inventory or disabled capability. Future category text
and additional native fields are preserved.

Partition mount text retains the connected target's `PathStyle`; nonempty text
can be explicitly converted to `TargetPath` with `mount_point()`. Empty text
returns `None`. Native placeholders remain literal values, and conversion does
not establish that a mount exists. `native_mount_point()` exposes the exact
private text. Direct deserialization outside a `Client` does not supply target
context, so converting nonempty mount text then returns an error.

Native backend/permission errors remain errors even when HTTP status is 200.
The API error operation identifies the CPU, memory, block or network read;
its explicit response diagnostic retains the native error without logging it.
The fixed macOS core has produced CPU and block inventories, but returns native
not-implemented errors for memory and network inventory. Those refusals are not
positive support evidence. Other platforms, fields and permissions retain their
actual native conditions and require final candidate validation. Malformed or
missing schemas are invalid responses rather than empty data.

Inventories can contain hardware addresses, serial numbers, identifiers,
filesystem labels, mount locations and other private data. Their normal Debug
formatting omits values, including nested records and unknown fields. Explicit
field access remains the caller's choice; do not log or upload it implicitly.
