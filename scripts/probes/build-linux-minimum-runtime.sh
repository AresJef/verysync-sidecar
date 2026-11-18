#!/usr/bin/env bash
set -euo pipefail

test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.17'
target=${1:-x86_64-unknown-linux-gnu}
case "$target" in
  x86_64-unknown-linux-gnu) expected_loader=/lib64/ld-linux-x86-64.so.2 ;;
  i686-unknown-linux-gnu) expected_loader=/lib/ld-linux.so.2 ;;
  aarch64-unknown-linux-gnu) expected_loader=/lib/ld-linux-aarch64.so.1 ;;
  s390x-unknown-linux-gnu) expected_loader=/lib/ld64.so.1 ;;
  *) exit 2 ;;
esac
export PATH="/toolchain/bin:$PATH"
export RUSTC=/toolchain/bin/rustc
export CARGO_HOME=/evidence/cargo
export CARGO_TARGET_DIR=/evidence/target

mkdir /evidence/project
cp -R /candidate/. /evidence/project/
cp /support/linux_minimum_runtime.rs /evidence/project/examples/linux_minimum_runtime.rs
cd /evidence/project
rustc --version
rustc -vV | grep -Fx "host: $target"
gcc --version | sed -n '1p'
cargo build --locked --release --target "$target" --example linux_minimum_runtime
binary="$CARGO_TARGET_DIR/$target/release/examples/linux_minimum_runtime"
mkdir /evidence/guest-runtime
guest=/evidence/guest-runtime

interpreter=$(readelf -l "$binary" | sed -n 's/.*Requesting program interpreter: \([^]]*\)\].*/\1/p')
test "$interpreter" = "$expected_loader"
install -m 755 "$binary" "$guest/vs-sdk-probe"
install -m 755 "$interpreter" "$guest/${interpreter##*/}"
gcc -std=gnu11 -Wall -Wextra -Werror -O2 /support/linux_guest_entropy.c -o "$guest/vs-entropy-control"
test "$(readelf -l "$guest/vs-entropy-control" | sed -n 's/.*Requesting program interpreter: \([^]]*\)\].*/\1/p')" = "$interpreter"
ldd "$binary" | tee /evidence/linked-libraries.txt
if grep -F 'not found' /evidence/linked-libraries.txt; then exit 1; fi
while read -r dependency; do
  test -f "$dependency"
  target="$guest/${dependency##*/}"
  if [ -e "$target" ]; then
    cmp "$dependency" "$target"
  else
    install -m 755 "$dependency" "$target"
  fi
done < <(awk '$2 == "=>" && $3 ~ /^\// {print $3}' /evidence/linked-libraries.txt)
test -f "$guest/libc.so.6"
readelf --version-info "$binary" > /evidence/symbol-versions.txt
readelf --version-info "$guest/vs-entropy-control" >> /evidence/symbol-versions.txt
highest=$(grep -Eo 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' /evidence/symbol-versions.txt | sort -Vu | tail -n 1)
test "$(printf '%s\n' "$highest" GLIBC_2.17 | sort -V | tail -n 1)" = GLIBC_2.17
sha256sum "$guest"/* > /evidence/guest-runtime-sha256.txt
