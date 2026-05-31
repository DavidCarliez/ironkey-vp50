#!/usr/bin/env python3
"""
Native Linux unlock helper for Kingston IronKey VaultPrivacy 50.

This talks to the device with Linux SG_IO and sends only the vendor login
command recovered from the bundled macOS application. It does not format,
reset, partition, or write to the decrypted filesystem.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import getpass
import hashlib
import os
import pathlib
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass


SG_IO = 0x2285
SG_DXFER_NONE = -1
SG_DXFER_TO_DEV = -2
SG_DXFER_FROM_DEV = -3

KINGSTON_USB_VENDOR = "0951"
VP50_USB_PRODUCT = "1576"

PVC_SECURE_MARK_FULL_MASKS = (0x03, 0x0C, 0x30, 0xC0)
PVC_SECURE_MARK_PARTIAL1_MASKS = (0x01, 0x04, 0x10, 0x40)
PVC_SECURE_MARK_PARTIAL2_MASKS = (0x02, 0x08, 0x20, 0x80)

PVC0_HASH_VALUES = (
    0x006A, 0x01ED, 0x0267, 0x03B9, 0x048B, 0x05CF, 0x0683, 0x07F2,
    0x08A0, 0x09D6, 0x0A22, 0x0B7F, 0x0CB8, 0x0DA3, 0x0E58, 0x0FC4,
    0x1074, 0x11E7, 0x12DB, 0x1347, 0x142B, 0x159D, 0x16DC, 0x17D5,
    0x1809, 0x19AF, 0x1A8B, 0x1BEF, 0x1C1C, 0x1DB9, 0x1EC8, 0x1FB8,
    0x2094, 0x219C, 0x22E6, 0x2341, 0x24CC, 0x25AF, 0x26E1, 0x27D5,
    0x2884, 0x297D, 0x2A8D, 0x2BCC, 0x2C79, 0x2DE1, 0x2EBA, 0x2F18,
    0x3021, 0x315C, 0x3280, 0x33B7, 0x345C, 0x354E, 0x3610, 0x37DD,
    0x3864, 0x3942, 0x3AFF, 0x3BAC, 0x3CBC, 0x3DBD, 0x3E16, 0x3F84,
)

STANDARD_RSA_512_KEYS = (
    (
        bytes.fromhex(
            "cd817255c6aa45dfbefae639997e2d86a92c0b7b137030f54022d1c0ece2842b"
            "b788bb6cbe0c0d65072eb3e230043f8a06166831ad94525e7800440311f9c0ea"
        ),
        bytes.fromhex(
            "61c41f807d833061667e94c73dbf0a7aee366b642ff987ca8a801b0b3098b194"
            "0b1d70586005e9ae4d16b6665ae24dc3ab98384b74d81eaac4a475fd7ec35db0"
        ),
        bytes.fromhex(
            "4d4fec95295bd9bec58d7f291a5479881f0bee4b9aafd485f1616001323c4b06"
            "2be4a6c1c25c387189032c96a6e98113be2bf4019322a1bdc1283975a483ce10"
        ),
    ),
)


class SgIoHdr(ctypes.Structure):
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


@dataclass(frozen=True)
class SgResult:
    status: int
    masked_status: int
    host_status: int
    driver_status: int
    resid: int
    duration_ms: int
    sense: bytes
    data: bytes

    @property
    def ok(self) -> bool:
        return (
            self.status == 0
            and self.host_status == 0
            and self.driver_status == 0
        )


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def sysfs_text(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return None


def discover_vp50_sg_devices() -> list[str]:
    devices: list[str] = []
    for sg in sorted(pathlib.Path("/sys/class/scsi_generic").glob("sg*")):
        dev = sg / "device"
        vendor = sysfs_text(dev / "vendor")
        model = sysfs_text(dev / "model")
        if vendor == "Kingston" and model == "VaultPrivacy50":
            devices.append(f"/dev/{sg.name}")
            continue

        # Fallback for systems whose SCSI strings differ but USB IDs are present.
        uevent = sysfs_text(dev / "uevent") or ""
        if KINGSTON_USB_VENDOR in uevent and VP50_USB_PRODUCT in uevent:
            devices.append(f"/dev/{sg.name}")
    return devices


def describe_current_device_state() -> None:
    print("Current block view:")
    cp = run(["lsblk", "-o", "NAME,PATH,MODEL,VENDOR,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINTS"])
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        print(cp.stderr.rstrip(), file=sys.stderr)

    print("\nMatching sg devices:")
    devices = discover_vp50_sg_devices()
    if devices:
        for dev in devices:
            print(f"  {dev}")
    else:
        print("  none found")


def sg_io(
    dev_path: str,
    cdb: bytes,
    *,
    direction: int = SG_DXFER_NONE,
    data_out: bytes = b"",
    data_in_len: int = 0,
    timeout_ms: int = 3000,
) -> SgResult:
    if len(cdb) > 16:
        raise ValueError("this helper supports CDBs up to 16 bytes")

    cdb_buf = ctypes.create_string_buffer(cdb)
    sense_buf = ctypes.create_string_buffer(64)

    if direction == SG_DXFER_TO_DEV:
        data_buf = ctypes.create_string_buffer(data_out)
        dxfer_len = len(data_out)
    elif direction == SG_DXFER_FROM_DEV:
        data_buf = ctypes.create_string_buffer(data_in_len)
        dxfer_len = data_in_len
    else:
        data_buf = None
        dxfer_len = 0

    hdr = SgIoHdr()
    hdr.interface_id = ord("S")
    hdr.dxfer_direction = direction
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = ctypes.sizeof(sense_buf)
    hdr.dxfer_len = dxfer_len
    hdr.dxferp = ctypes.cast(data_buf, ctypes.c_void_p).value if data_buf is not None else None
    hdr.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p).value
    hdr.sbp = ctypes.cast(sense_buf, ctypes.c_void_p).value
    hdr.timeout = timeout_ms

    mode = "r+b" if direction == SG_DXFER_TO_DEV else "rb"
    with open(dev_path, mode, buffering=0) as dev:
        fcntl.ioctl(dev.fileno(), SG_IO, hdr)

    data = b""
    if direction == SG_DXFER_FROM_DEV and data_buf is not None:
        data = bytes(data_buf.raw[: max(0, data_in_len - max(hdr.resid, 0))])

    return SgResult(
        status=hdr.status,
        masked_status=hdr.masked_status,
        host_status=hdr.host_status,
        driver_status=hdr.driver_status,
        resid=hdr.resid,
        duration_ms=hdr.duration,
        sense=bytes(sense_buf.raw[: hdr.sb_len_wr]),
        data=data,
    )


def format_result(result: SgResult) -> str:
    lines = [
        f"status=0x{result.status:02x} masked=0x{result.masked_status:02x} "
        f"host=0x{result.host_status:04x} driver=0x{result.driver_status:04x} "
        f"resid={result.resid} duration_ms={result.duration_ms}"
    ]
    if result.sense:
        lines.append(f"sense={result.sense.hex(' ')}")
    if result.data:
        lines.append(f"data={result.data.hex(' ')}")
    return "\n".join(lines)


def inquiry(dev_path: str) -> SgResult:
    cdb = bytes([0x12, 0, 0, 0, 96, 0])
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=96, timeout_ms=3000)


def read_area_parameters(dev_path: str, private_area: int) -> SgResult:
    if not 0 <= private_area <= 255:
        raise ValueError("private area must be between 0 and 255")
    # Recovered from -[VendorInterface NTU_Get_Area_Parameters:PrivateArea:].
    cdb = bytes([0xFF, 0xA0, 0x00, private_area] + [0x00] * 12)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=16, timeout_ms=3000)


def read_area_parameters_ext(dev_path: str, private_area: int, user_id: int) -> SgResult:
    for name, value in {"private_area": private_area, "user_id": user_id}.items():
        if not 0 <= value <= 255:
            raise ValueError(f"{name} must be between 0 and 255")
    # Recovered from -[VendorInterface NTU_Get_Area_ParametersExt:UserID:PrivateArea:].
    cdb = bytes([0xFF, 0xA0, 0x00, private_area, user_id] + [0x00] * 11)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x28, timeout_ms=3000)


def read_device_configuration(dev_path: str) -> SgResult:
    # Recovered from -[VendorInterface NTU_Get_Device_Configuration:].
    cdb = bytes([0xFF, 0x21, 0x00, 0x00, 0x02, 0x00, 0x00] + [0x00] * 9)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x200, timeout_ms=3000)


def read_attempt_counts(dev_path: str, area: int) -> SgResult:
    if not 0 <= area <= 0xFFFF:
        raise ValueError("area must be between 0 and 65535")
    # Recovered from -[VendorInterface NTU__Get_Current_Number_of_Attempts:RdNOA:WtNOA:].
    cdb = bytes([0xFF, 0x68, 0x00, area & 0xFF, (area >> 8) & 0xFF] + [0x00] * 11)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=2, timeout_ms=3000)


def read_rsa_device_public_key(dev_path: str) -> SgResult:
    # Recovered from -[VendorInterface NTU__RSA_Get_Device_Public_Key:size:].
    cdb = bytes([0xFF, 0x81, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x80, timeout_ms=3000)


def read_rsa_device_random_challenge(dev_path: str) -> SgResult:
    # Recovered from -[VendorInterface NTU__RSA_Get_Device_Random_Challenge:size:].
    cdb = bytes([0xFF, 0x85, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x40, timeout_ms=3000)


def read_secure_session_type(dev_path: str) -> SgResult:
    # Recovered from -[VendorInterface NTU__Get_Secure_Session_Type:DomainIndex:].
    cdb = bytes([0xFF, 0x8A, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=8, timeout_ms=3000)


def send_rsa_host_public_key(dev_path: str, data: bytes) -> SgResult:
    if len(data) != 0x80:
        raise ValueError("host public key payload must be 128 bytes")
    cdb = bytes([0xFF, 0x82, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_TO_DEV, data_out=data, timeout_ms=3000)


def send_rsa_host_random_challenge(dev_path: str, data: bytes) -> SgResult:
    if len(data) != 0x40:
        raise ValueError("host random challenge must be 64 bytes")
    cdb = bytes([0xFF, 0x83, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_TO_DEV, data_out=data, timeout_ms=3000)


def read_rsa_verify_device_public_key(dev_path: str) -> SgResult:
    cdb = bytes([0xFF, 0x84, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x40, timeout_ms=3000)


def send_rsa_verify_host_public_key(dev_path: str, data: bytes) -> SgResult:
    if len(data) != 0x40:
        raise ValueError("host public key verification payload must be 64 bytes")
    cdb = bytes([0xFF, 0x86, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_TO_DEV, data_out=data, timeout_ms=3000)


def send_rsa_host_secret_number(dev_path: str, data: bytes) -> SgResult:
    if len(data) != 0x40:
        raise ValueError("host secret payload must be 64 bytes")
    cdb = bytes([0xFF, 0x87, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_TO_DEV, data_out=data, timeout_ms=3000)


def read_rsa_device_secret_number(dev_path: str) -> SgResult:
    cdb = bytes([0xFF, 0x88, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_FROM_DEV, data_in_len=0x40, timeout_ms=3000)


def start_secure_access(dev_path: str, domain_index: int, secure_type: int) -> SgResult:
    for name, value in {"domain_index": domain_index, "secure_type": secure_type}.items():
        if not 0 <= value <= 255:
            raise ValueError(f"{name} must be between 0 and 255")
    cdb = bytes([0xFF, 0x8B, 0x00, domain_index, secure_type] + [0x00] * 11)
    return sg_io(dev_path, cdb, direction=SG_DXFER_NONE, timeout_ms=3000)


def terminate_secure_session(dev_path: str) -> SgResult:
    cdb = bytes([0xFF, 0x89, 0x00] + [0x00] * 13)
    return sg_io(dev_path, cdb, direction=SG_DXFER_NONE, timeout_ms=3000)


def pvc_func_open(dev_path: str, secure_mark_index: int, data: bytes) -> SgResult:
    if not 0 <= secure_mark_index <= 3:
        raise ValueError("secure mark index must be between 0 and 3")
    if len(data) != 0x40:
        raise ValueError("PVC open payload must be 64 bytes")
    cdb = bytes([0xFF, 0x8F, 0x00, 0x02, secure_mark_index] + [0x00] * 11)
    return sg_io(dev_path, cdb, direction=SG_DXFER_TO_DEV, data_out=data, timeout_ms=3000)


def mcu_read_page(dev_path: str, page: bytes) -> SgResult:
    if len(page) > 6:
        raise ValueError("page id must be at most 6 bytes")
    # Recovered from -[VendorInterface MCU_ReadPage:buffer:size:].
    cdb = bytearray(16)
    cdb[0] = 0x06
    cdb[1] = 0x05
    cdb[2 : 2 + len(page)] = page
    cdb[8] = 0x80
    return sg_io(dev_path, bytes(cdb), direction=SG_DXFER_FROM_DEV, data_in_len=0x210, timeout_ms=3000)


def pvc0_key() -> bytes:
    key = bytearray(64)
    for value in PVC0_HASH_VALUES:
        index = (value >> 8) & 0xFF
        if index >= len(key):
            raise ValueError(f"PVC0 hash index out of range: {index}")
        key[index] = value & 0xFF
    return bytes(key)


def pvc_secure_mark_type(raw_type: int) -> int:
    if raw_type == 0x17:
        return 1
    if raw_type >= 0x18:
        return 2
    return 0


def pvc_secure_mark_state(status_bits: int, index: int) -> tuple[int, str]:
    if not 0 <= index <= 3:
        raise ValueError("secure mark index must be between 0 and 3")
    full = PVC_SECURE_MARK_FULL_MASKS[index]
    partial1 = PVC_SECURE_MARK_PARTIAL1_MASKS[index]
    partial2 = PVC_SECURE_MARK_PARTIAL2_MASKS[index]
    masked = status_bits & full
    if masked == full:
        return 0, "open/active"
    if masked == 0:
        return 1, "closed/inactive"
    if masked == partial1:
        return 2, "partial-state-1"
    if masked == partial2:
        return 3, "partial-state-2"
    return 0xFF, "unknown"


def le_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def le_bytes(value: int, length: int = 64) -> bytes:
    return value.to_bytes(length, "little")


def random_number_below(modulus: int) -> int:
    if modulus <= 2:
        raise ValueError("invalid RSA modulus")
    return secrets.randbelow(modulus - 1) + 1


def aes_128_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    if len(data) % 16:
        raise ValueError("AES ECB data length must be a multiple of 16")
    cp = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.decode("utf-8", "replace").strip() or "openssl AES failed")
    return cp.stdout


def encrypt_pvc_key_type2(pvc_key: bytes, secure_key: bytes) -> bytes:
    if len(pvc_key) != 64:
        raise ValueError("PVC key must be 64 bytes")
    if len(secure_key) != 16:
        raise ValueError("secure key must be 16 bytes")
    block = bytearray(64)
    block[0:32] = hashlib.sha256(pvc_key).digest()
    block[32:48] = secure_key
    digest = hashlib.sha256(bytes(block[:48])).digest()
    plain = digest + os.urandom(32)
    return aes_128_ecb_encrypt(secure_key, plain)


def open_secure_session(dev_path: str, secure_type: int, domain_index: int, verbose: bool = False) -> bytes:
    host_modulus, host_public, host_private = STANDARD_RSA_512_KEYS[0]

    result = read_rsa_device_public_key(dev_path)
    if verbose:
        print("rsa-device-public-key:", format_result(result), sep="\n")
    if not result.ok or len(result.data) < 0x80:
        raise RuntimeError("failed to read device RSA public key")
    device_modulus = result.data[:64]
    device_public = result.data[64:128]
    n_device = le_int(device_modulus)
    e_device = le_int(device_public)
    n_host = le_int(host_modulus)
    e_host = le_int(host_public)
    d_host = le_int(host_private)

    result = send_rsa_host_public_key(dev_path, host_modulus + host_public)
    if verbose:
        print("rsa-set-host-public-key:", format_result(result), sep="\n")
    if not result.ok:
        raise RuntimeError("device rejected host RSA public key")

    host_challenge = random_number_below(n_device)
    host_challenge_bytes = le_bytes(host_challenge)
    result = send_rsa_host_random_challenge(dev_path, host_challenge_bytes)
    if verbose:
        print("rsa-set-host-random-challenge:", format_result(result), sep="\n")
    if not result.ok:
        raise RuntimeError("device rejected host random challenge")

    result = read_rsa_verify_device_public_key(dev_path)
    if verbose:
        print("rsa-verify-device-public-key:", format_result(result), sep="\n")
    if not result.ok or len(result.data) < 64:
        raise RuntimeError("failed to verify device public key")
    recovered = pow(le_int(result.data[:64]), e_device, n_device)
    if recovered != host_challenge:
        raise RuntimeError("device RSA verification response did not match host challenge")

    result = read_rsa_device_random_challenge(dev_path)
    if verbose:
        print("rsa-device-random-challenge:", format_result(result), sep="\n")
    if not result.ok or len(result.data) < 64:
        raise RuntimeError("failed to read device random challenge")
    device_challenge = le_int(result.data[:64])
    device_challenge_response = le_bytes(pow(device_challenge, d_host, n_host))
    result = send_rsa_verify_host_public_key(dev_path, device_challenge_response)
    if verbose:
        print("rsa-verify-host-public-key:", format_result(result), sep="\n")
    if not result.ok:
        raise RuntimeError("device rejected host public-key verification")

    host_secret = random_number_below(n_device)
    host_secret_bytes = le_bytes(host_secret)
    encrypted_host_secret = le_bytes(pow(host_secret, e_device, n_device))
    result = send_rsa_host_secret_number(dev_path, encrypted_host_secret)
    if verbose:
        print("rsa-set-host-secret-number:", format_result(result), sep="\n")
    if not result.ok:
        raise RuntimeError("device rejected host secret")

    result = read_rsa_device_secret_number(dev_path)
    if verbose:
        print("rsa-device-secret-number:", format_result(result), sep="\n")
    if not result.ok or len(result.data) < 64:
        raise RuntimeError("failed to read device secret")
    device_secret = pow(le_int(result.data[:64]), d_host, n_host)
    device_secret_bytes = le_bytes(device_secret)
    secure_key = bytes(a ^ b for a, b in zip(device_secret_bytes[:16], host_secret_bytes[:16]))

    if secure_type in (2, 3, 4):
        result = start_secure_access(dev_path, domain_index, secure_type)
        if verbose:
            print("start-secure-access:", format_result(result), sep="\n")
        if not result.ok:
            raise RuntimeError("device rejected start-secure-access")
    return secure_key


def cd_unlock(dev_path: str, index: int) -> SgResult:
    if not 0 <= index <= 255:
        raise ValueError("index must be between 0 and 255")
    # Recovered from -[VendorInterface NTU_CD__Unlock:].
    cdb = bytes([0xFF, 0x41, 0x00, index] + [0x00] * 12)
    return sg_io(dev_path, cdb, direction=SG_DXFER_NONE, timeout_ms=3000)


def derive_password_material(password: str, mode: str) -> bytes:
    password_bytes = password.encode("utf-8")
    if mode == "vendor-auto":
        mode = "md5" if len(password_bytes) >= 17 else "raw16"

    if mode == "raw16":
        if len(password_bytes) > 16:
            raise ValueError("raw16 mode only accepts passwords up to 16 UTF-8 bytes")
        return password_bytes.ljust(16, b"\x00")

    if mode == "md5":
        return hashlib.md5(password_bytes).digest()

    raise ValueError(f"unknown password derivation mode: {mode}")


def build_unlock_cdb(domain: int, user: int, time_interval: int, auto_logout: int) -> bytes:
    for name, value in {
        "domain": domain,
        "user": user,
        "time_interval": time_interval,
        "auto_logout": auto_logout,
    }.items():
        if not 0 <= value <= 255:
            raise ValueError(f"{name} must be between 0 and 255")

    # Recovered from -[VendorInterface NTU_Open:buffer:size:UserIDIndex:TimeInterval:AutoLogout:].
    return bytes([0xFF, 0xA4, 0x00, domain, user, time_interval, auto_logout] + [0x00] * 9)


def require_explicit_unlock_confirmation(args: argparse.Namespace) -> None:
    if args.yes:
        return
    print("This will send exactly one IronKey password unlock command.")
    print("A wrong password may count against the device's retry limit.")
    answer = input("Type UNLOCK to continue: ")
    if answer != "UNLOCK":
        raise SystemExit("aborted")


def rescan_and_show() -> None:
    run(["udevadm", "settle"])
    time.sleep(1)
    describe_current_device_state()


def cmd_probe(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = inquiry(dev)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    if result.ok and result.data:
        print("INQUIRY ASCII:", result.data[8:36].decode("ascii", "replace").strip())
    return 0 if result.ok else 1


def cmd_status(args: argparse.Namespace) -> int:
    describe_current_device_state()
    return 0


def cmd_area(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = read_area_parameters(dev, args.private_area)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    return 0 if result.ok else 1


def cmd_area_ext(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = read_area_parameters_ext(dev, args.private_area, args.user_id)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    return 0 if result.ok else 1


def cmd_config(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = read_device_configuration(dev)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    return 0 if result.ok else 1


def cmd_attempts(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = read_attempt_counts(dev, args.area)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    if result.ok and len(result.data) >= 2:
        print(f"read_attempts={result.data[0]} write_attempts={result.data[1]}")
    return 0 if result.ok else 1


def cmd_secure_probe(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    probes = [
        ("rsa-device-public-key", read_rsa_device_public_key),
        ("rsa-device-random-challenge", read_rsa_device_random_challenge),
        ("secure-session-type", read_secure_session_type),
    ]
    print(f"Using {dev}")
    ok = True
    for name, func in probes:
        try:
            result = func(dev)
        except PermissionError:
            print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"{name}: could not open or send SG_IO to {dev}: {exc}", file=sys.stderr)
            return 2
        print(f"\n{name}:")
        print(format_result(result))
        ok = ok and result.ok
        if name == "secure-session-type" and result.ok and len(result.data) >= 2:
            print(f"secure_type={result.data[0]} domain_index={result.data[1]}")
    return 0 if ok else 1


def cmd_secure_session(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        secure_key = open_secure_session(dev, args.secure_type, args.domain_index, verbose=args.verbose)
        print(f"secure_key_sha256={hashlib.sha256(secure_key).hexdigest()}")
        if args.open_pvc0:
            payload = encrypt_pvc_key_type2(pvc0_key(), secure_key)
            result = pvc_func_open(dev, args.secure_mark_index, payload)
            print("pvc-func-open:")
            print(format_result(result))
            if not result.ok:
                return 1
        if args.terminate:
            result = terminate_secure_session(dev)
            print("terminate-secure-session:")
            print(format_result(result))
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Secure session failed: {exc}", file=sys.stderr)
        try:
            terminate_secure_session(dev)
        except Exception:
            pass
        return 1
    return 0


def cmd_mcu_read(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    page = args.page.encode("ascii")
    print(f"Using {dev}")
    try:
        result = mcu_read_page(dev, page)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    print(format_result(result))
    if result.ok and len(result.data) >= 0x200:
        secure_mark_type = result.data[0x1FF]
        status_bits = result.data[0x4A] if len(result.data) > 0x4A else 0
        print(f"secure_mark_type_byte=0x{secure_mark_type:02x} status_bits_byte=0x{status_bits:02x}")
    return 0 if result.ok else 1


def cmd_pvc_status(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    try:
        result = mcu_read_page(dev, b"RD")
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    if not result.ok:
        print(format_result(result))
        return 1
    if len(result.data) < 0x200:
        print(f"Short MCU page: {len(result.data)} bytes", file=sys.stderr)
        return 1

    raw_type = result.data[0x1FF]
    status_bits = result.data[0x4A]
    mark_type = pvc_secure_mark_type(raw_type)
    print(f"secure_mark_type_raw=0x{raw_type:02x} secure_mark_type={mark_type}")
    print(f"status_bits=0x{status_bits:02x}")
    for index in range(4):
        code, label = pvc_secure_mark_state(status_bits, index)
        print(f"secure_mark[{index}]=0x{code:02x} {label}")
    return 0


def cmd_pvc0_key(args: argparse.Namespace) -> int:
    key = pvc0_key()
    print(f"pvc0_key={key.hex()}")
    print(f"sha256={hashlib.sha256(key).hexdigest()}")
    return 0


def cmd_cd_unlock(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    print(f"Using {dev}")
    print(f"CDB: {bytes([0xFF, 0x41, 0x00, args.index] + [0x00] * 12).hex(' ')}")
    if args.dry_run:
        print("Dry run only; no command sent.")
        return 0
    try:
        result = cd_unlock(dev, args.index)
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Could not open or send SG_IO to {dev}: {exc}", file=sys.stderr)
        return 2
    print(format_result(result))
    return 0 if result.ok else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    dev = args.sg or first_sg_or_die()
    if args.password and args.password_stdin:
        print("--password and --password-stdin cannot be used together", file=sys.stderr)
        return 2

    password = args.password
    if args.password_stdin:
        password = sys.stdin.read()
        if password.endswith("\n"):
            password = password[:-1]
    elif password is None and args.dry_run:
        password = ""
    elif password is None:
        password = getpass.getpass("IronKey password: ")

    try:
        material = derive_password_material(password, args.password_mode)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    cdb = build_unlock_cdb(args.domain, args.user, args.time_interval, args.auto_logout)
    print(f"Using {dev}")
    print(f"Password mode: {args.password_mode}")
    print(f"CDB: {cdb.hex(' ')}")
    print(f"PVC mode: {'enabled' if args.pvc else 'disabled'}")
    print(f"Data length: {len(material)} bytes")

    if args.dry_run:
        print("Dry run only; no command sent.")
        return 0

    if not args.pvc and not args.force_send:
        print("Plain unlock is guarded because this VP50 rejects the old opcode without PVC setup.", file=sys.stderr)
        print("Use --pvc for the native VP50 secure-session unlock path.", file=sys.stderr)
        return 2

    require_explicit_unlock_confirmation(args)

    try:
        if args.pvc:
            print("Opening PVC secure session...")
            secure_key = open_secure_session(dev, 0, 0, verbose=args.verbose)
            pvc_payload = encrypt_pvc_key_type2(pvc0_key(), secure_key)
            if args.pvc_secure_type in (2, 3, 4):
                result = start_secure_access(dev, args.domain, args.pvc_secure_type)
                print("start-secure-access:")
                print(format_result(result))
                if not result.ok:
                    terminate_secure_session(dev)
                    return 1
            result = pvc_func_open(dev, args.secure_mark_index, pvc_payload)
            print("pvc-func-open:")
            print(format_result(result))
            if not result.ok:
                terminate_secure_session(dev)
                return 1
            material = aes_128_ecb_encrypt(secure_key, material)

        result = sg_io(
            dev,
            cdb,
            direction=SG_DXFER_TO_DEV,
            data_out=material,
            timeout_ms=args.timeout_ms,
        )
    except PermissionError:
        print(f"Permission denied opening {dev}. Run with sudo/root or add temporary permissions.", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Could not open or send SG_IO to {dev}: {exc}", file=sys.stderr)
        if args.pvc:
            try:
                terminate_secure_session(dev)
            except Exception:
                pass
        return 2

    print(format_result(result))
    if args.pvc:
        term = terminate_secure_session(dev)
        print("terminate-secure-session:")
        print(format_result(term))
    if not result.ok:
        print("Unlock command failed or was rejected by the device.", file=sys.stderr)
        return 1

    print("Unlock command accepted by the SCSI layer. Waiting for the private LUN to appear...")
    rescan_and_show()
    return 0


def cmd_mount(args: argparse.Namespace) -> int:
    cp = run(["lsblk", "-J", "-o", "PATH,TRAN,TYPE,FSTYPE,MOUNTPOINTS,MODEL,VENDOR"])
    if cp.returncode != 0:
        print(cp.stderr.rstrip(), file=sys.stderr)
        return cp.returncode

    import json

    tree = json.loads(cp.stdout)
    candidates: list[str] = []

    def is_vp50(node: dict) -> bool:
        return node.get("vendor") == "Kingston" and node.get("model") == "VaultPrivacy50"

    def collect_unmounted_partitions(nodes: list[dict], under_vp50: bool = False) -> None:
        for node in nodes:
            node_is_vp50 = under_vp50 or is_vp50(node)
            path = node.get("path")
            if node_is_vp50 and node.get("type") == "part" and path and node.get("fstype"):
                mountpoints = node.get("mountpoints") or []
                if not any(mountpoints):
                    candidates.append(path)
            collect_unmounted_partitions(node.get("children") or [], node_is_vp50)

    collect_unmounted_partitions(tree.get("blockdevices") or [])
    if not candidates:
        print("No unmounted VaultPrivacy50 filesystem partition found.", file=sys.stderr)
        return 1

    dev = args.block or candidates[0]
    cmd = ["udisksctl", "mount", "-b", dev]
    if args.read_only:
        cmd = ["udisksctl", "mount", "-o", "ro", "-b", dev]
    print("Running:", " ".join(cmd))
    cp = run(cmd)
    if cp.stdout:
        print(cp.stdout.rstrip())
    if cp.stderr:
        print(cp.stderr.rstrip(), file=sys.stderr)
    return cp.returncode


def first_sg_or_die() -> str:
    devices = discover_vp50_sg_devices()
    if not devices:
        raise SystemExit("No Kingston VaultPrivacy50 sg device found. Is the USB stick connected?")
    return devices[0]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Native SG_IO helper for Kingston IronKey VaultPrivacy50 unlock/mount."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="show current lsblk view and matching sg devices")
    status.set_defaults(func=cmd_status)

    probe = sub.add_parser("probe", help="send standard SCSI INQUIRY to verify sg access")
    probe.add_argument("--sg", help="sg device, for example /dev/sg0")
    probe.set_defaults(func=cmd_probe)

    area = sub.add_parser("area", help="read vendor area parameters without a password")
    area.add_argument("--sg", help="sg device, for example /dev/sg1")
    area.add_argument("--private-area", type=int, default=0, help="private area index, default 0")
    area.set_defaults(func=cmd_area)

    area_ext = sub.add_parser("area-ext", help="read extended vendor area parameters without a password")
    area_ext.add_argument("--sg", help="sg device, for example /dev/sg0")
    area_ext.add_argument("--private-area", type=int, default=0, help="private area index, default 0")
    area_ext.add_argument("--user-id", type=int, default=0, help="user id, default 0")
    area_ext.set_defaults(func=cmd_area_ext)

    config = sub.add_parser("config", help="read vendor device configuration without a password")
    config.add_argument("--sg", help="sg device, for example /dev/sg0")
    config.set_defaults(func=cmd_config)

    attempts = sub.add_parser("attempts", help="read current password attempt counters")
    attempts.add_argument("--sg", help="sg device, for example /dev/sg0")
    attempts.add_argument("--area", type=int, default=0, help="area index, default 0")
    attempts.set_defaults(func=cmd_attempts)

    secure_probe = sub.add_parser("secure-probe", help="read RSA/session metadata without a password")
    secure_probe.add_argument("--sg", help="sg device, for example /dev/sg0")
    secure_probe.set_defaults(func=cmd_secure_probe)

    secure_session = sub.add_parser("secure-session", help="open the VP50 RSA secure session without sending a password")
    secure_session.add_argument("--sg", help="sg device, for example /dev/sg0")
    secure_session.add_argument("--secure-type", type=int, default=0, help="secure session type, default 0")
    secure_session.add_argument("--domain-index", type=int, default=0, help="secure session domain, default 0")
    secure_session.add_argument("--secure-mark-index", type=int, default=0, help="PVC secure mark index, default 0")
    secure_session.add_argument("--open-pvc0", action="store_true", help="also send PVC0 open payload")
    secure_session.add_argument("--terminate", action="store_true", help="terminate the secure session before exiting")
    secure_session.add_argument("--verbose", action="store_true", help="print each secure-session SG_IO result")
    secure_session.set_defaults(func=cmd_secure_session)

    mcu = sub.add_parser("mcu-read", help="read a 0x210-byte MCU status page")
    mcu.add_argument("--sg", help="sg device, for example /dev/sg0")
    mcu.add_argument("--page", default="RD", help="ASCII page id, default RD")
    mcu.set_defaults(func=cmd_mcu_read)

    pvc_status = sub.add_parser("pvc-status", help="read and decode the VP50 PVC secure-mark status")
    pvc_status.add_argument("--sg", help="sg device, for example /dev/sg0")
    pvc_status.set_defaults(func=cmd_pvc_status)

    pvc0_key_parser = sub.add_parser("pvc0-key", help="print the built-in PVC0 key recovered from the vendor app")
    pvc0_key_parser.set_defaults(func=cmd_pvc0_key)

    cd_unlock_parser = sub.add_parser("cd-unlock", help="send no-password virtual CD/control unlock command")
    cd_unlock_parser.add_argument("--sg", help="sg device, for example /dev/sg1")
    cd_unlock_parser.add_argument("--index", type=int, default=0, help="CD/control index byte, default 0")
    cd_unlock_parser.add_argument("--dry-run", action="store_true", help="print command but do not send it")
    cd_unlock_parser.set_defaults(func=cmd_cd_unlock)

    unlock = sub.add_parser("unlock", help="send one password unlock command")
    unlock.add_argument("--sg", help="sg device, for example /dev/sg0")
    unlock.add_argument("--password", help="password on command line; omitted prompts securely")
    unlock.add_argument("--password-stdin", action="store_true", help="read password from stdin")
    unlock.add_argument(
        "--password-mode",
        choices=["vendor-auto", "raw16", "md5"],
        default="vendor-auto",
        help="vendor-auto uses raw16 for <=16 UTF-8 bytes, MD5 for >=17 bytes",
    )
    unlock.add_argument("--domain", type=int, default=0, help="domain/profile index, default 0")
    unlock.add_argument("--user", type=int, default=0, help="user id index, default 0")
    unlock.add_argument("--time-interval", type=int, default=0, help="auto-lock interval byte, default 0")
    unlock.add_argument("--auto-logout", type=int, default=0, help="auto logout byte, default 0")
    unlock.add_argument("--timeout-ms", type=int, default=3000, help="SG_IO timeout")
    unlock.add_argument("--dry-run", action="store_true", help="print derived command shape but do not send it")
    unlock.add_argument("--pvc", action="store_true", help="use the VP50 PVC secure-session unlock path")
    unlock.add_argument("--pvc-secure-type", type=int, default=3, help="PVC secure access type, default 3")
    unlock.add_argument("--secure-mark-index", type=int, default=0, help="PVC secure mark index, default 0")
    unlock.add_argument("--verbose", action="store_true", help="print each secure-session SG_IO result")
    unlock.add_argument("--force-send", action="store_true", help=argparse.SUPPRESS)
    unlock.add_argument("-y", "--yes", action="store_true", help="skip interactive UNLOCK confirmation")
    unlock.set_defaults(func=cmd_unlock)

    mount = sub.add_parser("mount", help="mount the first unlocked private partition using udisksctl")
    mount.add_argument("--block", help="partition to mount, for example /dev/sda1")
    mount.add_argument("--read-only", action="store_true", help="ask udisksctl for a read-only mount")
    mount.set_defaults(func=cmd_mount)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
