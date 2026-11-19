#!/bin/sh
set -eux
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap 'status=$?; echo "RECEIVER_GUEST_FINISH status=$status"; sync; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
mkdir -p /dev/pts
mount -t devpts -o mode=620,ptmxmode=666 devpts /dev/pts
python3 -B -c 'import os, pty; master, slave = pty.openpty(); assert os.isatty(slave); os.close(slave); os.close(master)'
echo 'WIRE_GUEST_PTY_READY real_master_slave=true'
echo "RECEIVER_GUEST_BOOT kernel=$(uname -r) architecture=$(uname -m)"
set -- /sys/bus/vmbus/drivers/hv_netvsc/*/net/*
test "$#" = 1
test -e "$1"
link=${1##*/}
ip link set lo up
ip link set "$link" name peer
link=peer
ip link set "$link" up
ip addr add 192.0.2.2/30 dev "$link"
ip -6 addr add 2001:db8:73f:43::2/64 dev "$link"
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
echo "RECEIVER_GUEST_LINK name=$link boot_driver=hv_netvsc no_default_ipv4_ipv6=true"
insmod /af_packet.ko
python3 -B -c 'import socket; sock=socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)); sock.bind(("peer", 3)); sock.close()'
echo 'WIRE_GUEST_CAPTURE_READY real_af_packet_socket=true'
OWNED_HYPERV_QOS_CONTROL=true python3 -B /qos_receive.py
