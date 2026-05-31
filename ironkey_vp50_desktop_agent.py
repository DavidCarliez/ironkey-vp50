#!/usr/bin/env python3
"""
Desktop user-session agent for Kingston IronKey VaultPrivacy50 drives.

The agent watches for a locked VP50, asks for the password with kdialog or
zenity, passes it to ironkey_vp50.py through stdin, and mounts the unlocked
filesystem through udisksctl. It does not store the password.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import sys
import time

import ironkey_vp50


APP_NAME = "IronKey VP50"
VP50_VENDOR = "Kingston"
VP50_MODEL = "VaultPrivacy50"
LOG_PATH = pathlib.Path("/tmp/ironkey-vp50-desktop-agent.log")


def log(message: str) -> None:
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fp:
            fp.write(f"{timestamp} {message}\n")
    except OSError:
        pass


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def helper_path() -> str:
    return str(pathlib.Path(__file__).with_name("ironkey_vp50.py"))


def have_command(name: str) -> bool:
    return shutil.which(name) is not None


def notify(message: str, timeout: int = 6) -> None:
    if have_command("kdialog"):
        subprocess.Popen(
            ["kdialog", "--title", APP_NAME, "--passivepopup", message, str(timeout)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif have_command("zenity"):
        subprocess.Popen(
            ["zenity", "--notification", "--text", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    elif have_command("notify-send"):
        subprocess.Popen(
            ["notify-send", APP_NAME, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def ask_password() -> str | None:
    if have_command("kdialog"):
        log("showing kdialog password prompt")
        cp = run(["kdialog", "--title", APP_NAME, "--password", "Unlock Kingston IronKey VaultPrivacy50"])
        log(f"kdialog exited with {cp.returncode}")
    elif have_command("zenity"):
        log("showing zenity password prompt")
        cp = run(["zenity", "--password", "--title", APP_NAME])
        log(f"zenity exited with {cp.returncode}")
    else:
        log("no graphical password prompt command found")
        notify("Install kdialog or zenity for the IronKey password prompt.")
        return None

    if cp.returncode != 0:
        return None
    password = cp.stdout
    if password.endswith("\n"):
        password = password[:-1]
    if password.endswith("\r"):
        password = password[:-1]
    log("password received")
    return password


def lsblk_tree() -> list[dict]:
    cp = run(["lsblk", "-J", "-o", "PATH,MODEL,VENDOR,SIZE,TYPE,FSTYPE,MOUNTPOINTS"])
    if cp.returncode != 0:
        log(f"lsblk failed: {cp.stderr.strip()}")
        return []
    return json.loads(cp.stdout).get("blockdevices") or []


def is_vp50(node: dict) -> bool:
    return node.get("vendor") == VP50_VENDOR and node.get("model") == VP50_MODEL


def vp50_has_mounted_partition(nodes: list[dict]) -> bool:
    for node in nodes:
        if is_vp50(node):
            for child in node.get("children") or []:
                if child.get("type") == "part" and any(child.get("mountpoints") or []):
                    return True
        if vp50_has_mounted_partition(node.get("children") or []):
            return True
    return False


def vp50_has_unmounted_partition(nodes: list[dict]) -> bool:
    for node in nodes:
        if is_vp50(node):
            for child in node.get("children") or []:
                if child.get("type") == "part" and child.get("fstype") and not any(child.get("mountpoints") or []):
                    return True
        if vp50_has_unmounted_partition(node.get("children") or []):
            return True
    return False


def vp50_locked_present(nodes: list[dict]) -> bool:
    for node in nodes:
        if is_vp50(node) and node.get("type") == "disk" and node.get("size") == "0B":
            return True
        if vp50_locked_present(node.get("children") or []):
            return True
    return False


def mount_unlocked(read_only: bool) -> bool:
    if vp50_has_mounted_partition(lsblk_tree()):
        log("mount skipped: already mounted")
        return True

    cmd = [sys.executable, helper_path(), "mount"]
    if read_only:
        cmd.append("--read-only")
    cp = run(cmd)
    log(f"mount command exited with {cp.returncode}")
    if cp.returncode == 0:
        message = cp.stdout.strip() or "IronKey mounted."
        notify(message)
        return True
    if vp50_has_mounted_partition(lsblk_tree()):
        log("mount command reported failure, but VP50 is mounted")
        notify("IronKey mounted.")
        return True
    return False


def unlock_device(sg_dev: str, password: str) -> bool:
    cmd = [
        "sudo",
        "-n",
        "ironkey-vp50-root-unlock",
        sg_dev,
    ]
    log(f"unlocking {sg_dev}")
    cp = run(cmd, input=password)
    log(f"unlock command exited with {cp.returncode}")
    if cp.returncode == 127:
        cmd = [
            sys.executable,
            helper_path(),
            "unlock",
            "--sg",
            sg_dev,
            "--pvc",
            "--password-stdin",
            "--yes",
        ]
        log(f"root wrapper not found, retrying direct unlock for {sg_dev}")
        cp = run(cmd, input=password)
        log(f"direct unlock command exited with {cp.returncode}")
    if cp.returncode == 0:
        return True

    output = "\n".join(part for part in (cp.stdout.strip(), cp.stderr.strip()) if part)
    if output:
        log("unlock output begin")
        for line in output.splitlines():
            log(f"unlock output: {line}")
        log("unlock output end")
    if "Permission denied" in output:
        notify("Permission denied opening the IronKey sg device. Install the desktop integration udev rule.")
    elif output:
        notify(f"IronKey unlock failed: {output.splitlines()[-1]}")
    else:
        notify("IronKey unlock failed. Check the password and retry.")
    return False


def check_once(read_only: bool) -> bool:
    nodes = lsblk_tree()
    log(
        "state "
        f"mounted={vp50_has_mounted_partition(nodes)} "
        f"unmounted={vp50_has_unmounted_partition(nodes)} "
        f"locked={vp50_locked_present(nodes)}"
    )
    if vp50_has_mounted_partition(nodes):
        return True

    if vp50_has_unmounted_partition(nodes):
        return mount_unlocked(read_only)

    if not vp50_locked_present(nodes):
        return False

    sg_devices = ironkey_vp50.discover_vp50_sg_devices()
    log(f"sg_devices={sg_devices}")
    if not sg_devices:
        return False

    password = ask_password()
    if password is None:
        return False

    if unlock_device(sg_devices[0], password):
        for _ in range(10):
            if vp50_has_mounted_partition(lsblk_tree()):
                log("VP50 mounted after unlock")
                return True
            if vp50_has_unmounted_partition(lsblk_tree()):
                mount_unlocked(read_only)
                return True
            time.sleep(0.5)
        mount_unlocked(read_only)
        return True
    return False


def cmd_agent(args: argparse.Namespace) -> int:
    log("agent started")
    last_prompt = 0.0
    while True:
        nodes = lsblk_tree()
        if vp50_has_mounted_partition(nodes):
            if args.once:
                return 0
            time.sleep(args.poll_interval)
            continue

        if vp50_has_unmounted_partition(nodes):
            mount_unlocked(args.read_only)
            if args.once:
                return 0
            time.sleep(args.poll_interval)
            continue

        if vp50_locked_present(nodes) and time.monotonic() - last_prompt >= args.retry_delay:
            last_prompt = time.monotonic()
            check_once(args.read_only)

        if args.once:
            return 0
        time.sleep(args.poll_interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Desktop user-session agent for IronKey VP50 auto-unlock.")
    parser.add_argument("--once", action="store_true", help="check once and exit")
    parser.add_argument("--read-only", action="store_true", help="mount the unlocked partition read-only")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="poll interval in seconds")
    parser.add_argument("--retry-delay", type=float, default=300.0, help="minimum delay between password prompts")
    parser.set_defaults(func=cmd_agent)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
