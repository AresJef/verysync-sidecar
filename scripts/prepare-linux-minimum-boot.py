"""Prepare offline full-system boot fixtures from the pinned Debian package bytes."""
import argparse
import gzip
import hashlib
import io
import json
import os
import re
from pathlib import Path
import stat
import struct
import subprocess
import tarfile

KERNELS = {"squeeze": "2.6.32-5-amd64", "wheezy": "3.2.0-4-amd64"}
dig = lambda payload: hashlib.sha256(payload).hexdigest()

def verified_members(package, required):
    src = Path(package["local_path"])
    assert src.parent == WORK and src.stat().st_size == int(package["size"])
    assert dig(src.read_bytes()) == package["sha256"]
    index = subprocess.check_output(["/usr/bin/ar", "t", str(src)], text=True).splitlines()
    selected, = [name for name in index if name in {"data.tar.gz", "data.tar.xz", "data.tar.bz2"}]
    data = subprocess.check_output(["/usr/bin/ar", "p", str(src), selected])
    payloads = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for item in archive:
            name = item.name.removeprefix("./")
            if name not in required:
                continue
            assert item.isfile() and 0 < item.size <= required[name]
            assert name not in payloads
            file = archive.extractfile(item)
            assert file is not None
            payloads[name] = file.read()
            assert len(payloads[name]) == item.size
    assert set(payloads) == set(required)
    return payloads

def check_static_busybox(busybox):
    assert busybox[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<H", busybox,18)[0] == 62  # EM_X86_64
    table = struct.unpack_from("<Q",busybox,32)[0]
    size,count = struct.unpack_from("<HH",busybox,54)
    assert size == 56 and 0 < count < 64 and table + size*count < len(busybox)
    types = [struct.unpack_from("<I",busybox,table+i*size)[0] for i in range(count)]
    assert 3 not in types  # No PT_INTERP.

def write_newc(files):
    cpio = bytearray()
    for ino,(name, mode, data, major,minor) in enumerate(files+[("TRAILER!!!",0,b"",0,0)],1):
        encoded = name.encode("ascii")+b"\0"
        fields = (ino,mode,0,0,1,0,len(data),0,0,major,minor,len(encoded),0)
        cpio.extend(("070701"+"".join(f"{v:08x}" for v in fields)).encode())
        cpio.extend(encoded)
        cpio.extend(b"\0"*((-len(cpio))%4))
        cpio.extend(data)
        cpio.extend(b"\0"*((-len(cpio))%4))
    return bytes(cpio)

def prepare_runtime(runtime, engine_receipt):
    engine = json.loads(engine_receipt.read_text())
    assert (engine["package"],engine["version"]) == ("linux-amd64-standard","v2.33.2")
    binary = Path(engine["binary"])
    assert binary.is_file() and 1_000_000 < binary.stat().st_size < 150_000_000
    native_core = binary.read_bytes()
    digest = engine["binary_sha256"]
    assert re.fullmatch(r"[a-f0-9]{64}", digest) and dig(native_core) == digest
    assert native_core[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", native_core, 18)[0] == 62

    files = [(name, stat.S_IFDIR | mode, b"", 0, 0)
             for name,mode in (("etc",0o755),("lib64",0o755),("tmp",0o1777),
                               ("vs-data",0o755),("version-state",0o700))]
    files += [(name, stat.S_IFCHR | 0o666, b"", 1, minor)
              for name, minor in (("dev/random",8),("dev/urandom",9),("dev/zero",5))]
    files += [
        ("etc/passwd", stat.S_IFREG | 0o644,
         b"root:x:0:0:root:/:/bin/busybox\nvs-guest:x:1000:1000:guest:/vs-data:/bin/busybox\n",0,0),
        ("etc/group", stat.S_IFREG | 0o644,b"root:x:0:\nvs-guest:x:1000:\n",0,0),
        ("etc/hosts", stat.S_IFREG | 0o644,b"127.0.0.1 localhost\n",0,0),
        ("bin/verysync", stat.S_IFREG | 0o755,native_core,0,0),
    ]

    hashes = {"bin/verysync":digest}
    for source in sorted(runtime.iterdir()):
        assert source.is_file() and not source.is_symlink()
        assert 0 < source.stat().st_size < 100_000_000
        if source.name == "vs-sdk-probe":
            destination = "bin/vs-sdk-probe"
        else:
            assert re.fullmatch(r"(lib|ld-)[A-Za-z0-9_.+-]+",source.name)
            destination = "lib64/"+source.name
        data = source.read_bytes()
        assert data[:6] == b"\x7fELF\x02\x01"
        assert struct.unpack_from("<H",data,18)[0] == 62
        files.append((destination, stat.S_IFREG | 0o755,data,0,0))
        hashes[destination] = dig(data)
    assert {"lib64/libc.so.6","lib64/ld-linux-x86-64.so.2","bin/vs-sdk-probe"} <= hashes.keys()
    return files, hashes


def boot_init(expected, program_sha=None):
    runtime = ""
    if program_sha is not None:
        runtime = f'''/bin/busybox chown 1000:1000 /vs-data || fail guest_permissions
/bin/busybox chmod 0700 /vs-data || fail guest_permissions
actual_program_sha=$(/bin/busybox sha256sum /bin/verysync) || fail program_sha
case "$actual_program_sha" in "{program_sha} "*) ;; *) fail program_sha ;; esac
version=$(/bin/verysync version --home /version-state) || fail fixed_program_version
case "$version" in *v2.33.2*) ;; *) fail fixed_program_version ;; esac
echo "VS_MINIMUM_CORE_VERSION_OK v2.33.2"
/bin/vs-sdk-probe {program_sha} || fail sdk_runtime
'''
    return f"""#!/bin/busybox sh
export PATH=/bin
fail() {{
    echo "VS_MINIMUM_BOOT_FAILURE $1"
    /bin/busybox poweroff -f
    exit 1
}}
/bin/busybox mount -t proc proc /proc || fail proc
/bin/busybox mount -t sysfs sysfs /sys || fail sysfs
actual=$(/bin/busybox uname -r) || fail uname
[ "$actual" = "{expected}" ] || fail kernel_identity
/bin/busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up || fail loopback_setup
ifconfig_result=$(/bin/busybox ifconfig lo) || fail loopback_readback
case "$ifconfig_result" in *127.0.0.1*) ;; *) fail loopback_address ;; esac
echo "VS_MINIMUM_BOOT_OK kernel=$actual loopback=127.0.0.1"
{runtime}/bin/busybox sync
/bin/busybox poweroff -f
exit 0
""".encode()

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("distribution", choices=KERNELS)
parser.add_argument("--destination", required=True, type=Path)
parser.add_argument("--local-package-dir", type=Path,
                    help="Use already downloaded packages after the same byte checks")
parser.add_argument("--runtime-dir", type=Path)
parser.add_argument("--engine-receipt", type=Path)
args = parser.parse_args()
if (args.runtime_dir is None) != (args.engine_receipt is None):
    parser.error("provide both the fixed native engine receipt and runtime directory")
os.umask(0o077)
WORK = args.destination.resolve()
WORK.mkdir(mode=0o700)
manifest = Path(__file__).with_name("linux-minimum-boot-packages.json")
records = json.loads(manifest.read_text())[args.distribution]
by_name = {}
for package in records:
    filename = args.distribution+"-"+package["package"]+".deb"
    destination = WORK / filename
    if args.local_package_dir:
        destination.write_bytes((args.local_package_dir/filename).read_bytes())
    else:
        subprocess.run(["curl","--proto","=https","--silent","--show-error","--fail",
                        "--connect-timeout","10","--max-time","60","--max-filesize",package["size"],
                        "--output",str(destination),"https://archive.debian.org/debian/"+package["filename"]],
                       check=True)
    by_name[args.distribution,package["package"]] = dict(package,local_path=str(destination))
distribution = args.distribution
release=KERNELS[distribution]
kernel_name, config_name = "boot/vmlinuz-"+release, "boot/config-"+release
kernel_deb = by_name[distribution,"linux-image-"+release]
members = verified_members(kernel_deb, {kernel_name:12*1024*1024,config_name:1024*1024})
kernel,config = members[kernel_name],members[config_name]
assert kernel[0x202:0x206] == b"HdrS"
check = {"CONFIG_X86_64","CONFIG_BLK_DEV_INITRD","CONFIG_BINFMT_ELF","CONFIG_PROC_FS",
         "CONFIG_SYSFS","CONFIG_INET","CONFIG_SERIAL_8250_CONSOLE"}
config_set = {x for x in config.decode().splitlines() if not x.startswith("#")}
assert all(key+"=y" in config_set for key in check), (distribution,check-set(x.split("=")[0] for x in config_set))
busybox = verified_members(by_name[distribution,"busybox-static"], {"bin/busybox":2500000})["bin/busybox"]
check_static_busybox(busybox)
files=[(name,stat.S_IFDIR|0o755,b"",0,0) for name in ("bin","dev","proc","sys")]
files += [("dev/console",stat.S_IFCHR|0o600,b"",5,1),("dev/null",stat.S_IFCHR|0o666,b"",1,3),
          ("bin/busybox",stat.S_IFREG|0o755,busybox,0,0)]
runtime_hashes = {}
if args.runtime_dir is not None:
    runtime_files, runtime_hashes = prepare_runtime(args.runtime_dir,args.engine_receipt)
    files.extend(runtime_files)
files.append(("init",stat.S_IFREG|0o755,boot_init(release,runtime_hashes.get("bin/verysync")),0,0))
ramdisk = gzip.compress(write_newc(files),compresslevel=9,mtime=0)
root=WORK/distribution
root.mkdir(mode=0o700,exist_ok=True)
(root/"bzImage").write_bytes(kernel)
(root/"initramfs.cpio.gz").write_bytes(ramdisk)
(root/"kernel-config").write_bytes(config)
receipt = {"distribution":distribution,"expected_uname_release":release,
            "bzimage_sha256":dig(kernel),"initramfs_sha256":dig(ramdisk),
            "kernel_config_sha256":dig(config),"busybox_sha256":dig(busybox),
            "required_kernel_options":sorted(check),"exact_guest_initramfs":str(root/"initramfs.cpio.gz"),
            "expected_serial_marker":"VS_MINIMUM_BOOT_OK kernel="+release+" loopback=127.0.0.1",
            "qemu_network_adapters":0,"boot_performed":False,
            "runtime_payload_sha256":runtime_hashes}
(WORK/"prepared-boot-fixture.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt))
