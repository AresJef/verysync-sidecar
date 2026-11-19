#!/usr/bin/env bash
set -euo pipefail

source_tree="$1"
support="$2"
work="$3"
arch_profile="${4:-armel}"
case "$arch_profile" in
  armel)
    target=armv5te-unknown-linux-gnueabi
    abi=arm-linux-gnueabi
    cpu=armv5te
    float=soft
    loader=ld-linux.so.3
    ;;
  armv6)
    target=arm-unknown-linux-gnueabi
    abi=arm-linux-gnueabi
    cpu=armv6
    float=soft
    loader=ld-linux.so.3
    ;;
  armhf)
    target=armv7-unknown-linux-gnueabihf
    abi=arm-linux-gnueabihf
    cpu=armv7-a
    float=hard
    loader=ld-linux-armhf.so.3
    ;;
  *) exit 2 ;;
esac
sysroot="$work/armel-sysroot"
fixture="$work/guest-runtime"
mkdir -m 700 "$sysroot" "$fixture"

for package in libc6 libc6-dev libgcc1 libatomic1 linux-libc-dev; do
  dpkg-deb -x "$work/packages/stretch-$package.deb" "$sysroot"
done
test -f "$sysroot/lib/$abi/ld-2.24.so"
test -f "$sysroot/lib/$abi/libc-2.24.so"
test -f "$sysroot/usr/lib/$abi/libc.so"
for link in "$sysroot/usr/lib/$abi/"*.so; do
  if [[ ! -L "$link" ]]; then continue; fi
  destination=$(readlink "$link")
  if [[ "$destination" == "/lib/$abi/"* ]]; then
    test -f "$sysroot$destination"
    ln -sfn -- "../../../${destination#/}" "$link"
    test -f "$link"
  fi
done
test -f "$sysroot/usr/lib/$abi/libm.so"
test -f "$sysroot/usr/lib/$abi/libdl.so"
ln -s "../../../lib/$abi/libgcc_s.so.1" "$sysroot/usr/lib/$abi/libgcc_s.so"
ln -s "libatomic.so.1" "$sysroot/usr/lib/$abi/libatomic.so"

export VS_ARMEL_SYSROOT="$sysroot"
export VS_ARM_GNU_ABI="$abi" VS_ARM_CPU="$cpu" VS_ARM_FLOAT="$float"
linker="$work/gcc-armel-stretch"
cat > "$linker" <<'LINKER'
#!/usr/bin/env bash
set -euo pipefail
root="$VS_ARMEL_SYSROOT"
abi="$VS_ARM_GNU_ABI"
cpu=(-march="$VS_ARM_CPU" -mfloat-abi="$VS_ARM_FLOAT")
if [[ "$VS_ARM_FLOAT" = hard ]]; then cpu+=(-mfpu=vfpv3-d16); fi
exec "/usr/bin/$abi-gcc" --sysroot="$root" "${cpu[@]}" \
  -B"$root/usr/lib/$abi/" -L"$root/usr/lib/$abi" -L"$root/lib/$abi" \
  -isystem "$root/usr/include/$abi" -isystem "$root/usr/include" \
  -Wl,-rpath-link,"$root/lib/$abi" -Wl,-rpath-link,"$root/usr/lib/$abi" "$@"
LINKER
chmod 700 "$linker"

target_alias="${target//-/_}"
cargo_target_alias=$(printf '%s' "$target_alias" | tr '[:lower:]' '[:upper:]')
export "CARGO_TARGET_${cargo_target_alias}_LINKER=$linker"
export "CC_${target_alias}=$linker"
export "AR_${target_alias}=/usr/bin/$abi-ar"
export CARGO_TARGET_DIR="$work/target"
cargo +1.85.0 --version
rustc +1.85.0 --version
rustup target list --installed --toolchain 1.85.0 | grep -Fx "$target"
"$abi-gcc" --version | sed -n '1p'
printf 'Link target %s with archived ARM sysroot %s\n' "$target" "$sysroot"
cp -R "$source_tree" "$work/product"
cp "$support/linux_minimum_runtime.rs" "$work/product/examples/linux_minimum_runtime.rs"
(
  cd "$work/product"
  cargo +1.85.0 build --locked --release --target "$target" --example linux_minimum_runtime
)
install -m 755 "$CARGO_TARGET_DIR/$target/release/examples/linux_minimum_runtime" "$fixture/vs-sdk-probe"
"$linker" -std=gnu11 -Wall -Wextra -Werror -O2 "$support/linux_guest_entropy.c" -o "$fixture/vs-entropy-control"
install -m 755 "$sysroot/lib/$abi/ld-2.24.so" "$fixture/$loader"
install -m 755 "$sysroot/lib/$abi/libc-2.24.so" "$fixture/libc.so.6"

needed_libraries() {
  "$abi-readelf" -d "$1" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p'
}
runtime_dependencies=("$fixture/vs-sdk-probe" "$fixture/vs-entropy-control" "$fixture/libc.so.6")
for file in "${runtime_dependencies[@]:0:2}"; do
  "$abi-readelf" -l "$file" | grep -F "[Requesting program interpreter: /lib/$loader]"
done
for ((i = 0; i < ${#runtime_dependencies[@]}; i++)); do
  binary="${runtime_dependencies[i]}"
  while read -r name; do
    [[ "$name" =~ ^(lib|ld-)[0-9a-zA-Z_.+-]+$ ]]
    if [[ -f "$fixture/$name" ]]; then continue; fi
    input="$sysroot/lib/$abi/$name"
    if [[ ! -f "$input" ]]; then input="$sysroot/usr/lib/$abi/$name"; fi
    mapped=$(realpath "$input")
    case "$mapped" in "$sysroot/"*) ;; *) exit 1 ;; esac
    test -f "$mapped"
    install -m 755 "$mapped" "$fixture/$name"
    runtime_dependencies+=("$fixture/$name")
  done < <(needed_libraries "$binary")
done

"$abi-readelf" --version-info "$fixture/vs-sdk-probe" "$fixture/vs-entropy-control" > "$work/symbol-versions.txt"
highest=$(grep -Eo 'GLIBC_[0-9]+(\.[0-9]+)+' "$work/symbol-versions.txt" | sort -Vu | tail -n 1)
test "$(printf '%s\n' "$highest" GLIBC_2.24 | sort -V | tail -n 1)" = GLIBC_2.24
printf 'ARMEL dynamic glibc max symbol ABI %s\n' "$highest"
sha256sum "$fixture"/* | tee "$work/guest-runtime-sha256.txt"
