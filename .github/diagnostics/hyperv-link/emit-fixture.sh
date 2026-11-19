#!/usr/bin/env bash
set -euo pipefail

diagnostics=$(cd "$(dirname "$0")" && pwd)
work="$1"
mkdir -p "$work"
test ! -e "$work/ram" && test ! -e "$work/output"
cd "$work"
upstream=https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64
iso=alpine-virt-3.23.8-x86_64.iso
fs=alpine-minirootfs-3.23.8-x86_64.tar.gz
curl -fsSL --max-time 90 -o "$iso" "$upstream/$iso"
curl -fsSL --max-time 45 -o "$fs" "$upstream/$fs"
printf '%s  %s\n' \
  5e0879304cfbc433bcafd007f5ef88f6c717020bf739a7636b5d5598fd1b4671 "$iso" \
  56e2810205c17a5dff78cdd7b2c2af4ccdef16f18d765d5bb0f527438b136676 "$fs" | sha256sum -c -
mkdir -p ram iso-tree/boot/grub output
xorriso -osirrox on -indev "$iso" -extract /boot/vmlinuz-virt iso-tree/boot/vmlinuz
sudo tar --numeric-owner -xzf "$fs" -C ram
sudo mkdir -p ram/proc ram/sys ram/run ram/dev
cc -Os -static -Wall -Wextra -Werror "$diagnostics/guest-receiver.c" -o receive-probe
sudo install -m 0755 "$diagnostics/guest-init.sh" ram/init
sudo install -m 0755 receive-probe ram/bin/receive-probe
test -c ram/dev/console || sudo mknod -m 0600 ram/dev/console c 5 1
test -c ram/dev/null || sudo mknod -m 0666 ram/dev/null c 1 3
sudo sh -c 'cd ram && find . -print0 | cpio --null -o -H newc --quiet' | gzip -n -1 > iso-tree/boot/initramfs.cpio.gz
cat > iso-tree/boot/grub/grub.cfg <<'GRUB'
serial --unit=0 --speed=115200
terminal_output serial
set timeout=0
set default=0
menuentry 'Disposable receive fixture' {
  echo RECEIVER_GRUB_BOOT
  linux /boot/vmlinuz console=ttyS0,115200n8 panic=0
  initrd /boot/initramfs.cpio.gz
}
GRUB
grub-mkrescue -d /usr/lib/grub/x86_64-efi -o output/receive.iso iso-tree
(cd output && sha256sum receive.iso > SHA256SUMS)
cat output/SHA256SUMS
