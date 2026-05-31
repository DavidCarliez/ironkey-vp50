# Kingston IronKey VaultPrivacy50 Linux Helper

Native Linux SG_IO helper for unlocking and mounting a Kingston IronKey
VaultPrivacy50 USB drive when you know the device password.

This does not use Wine and does not call the vendor Windows or macOS binaries.
It talks directly to the drive through Linux SCSI generic (`/dev/sg*`) devices.

## Scope

- Supported device tested so far: Kingston IronKey VaultPrivacy50
  (`0951:1576`).
- `status` shows the Linux block and sg device view.
- `probe` sends standard SCSI INQUIRY to confirm sg access.
- `unlock --pvc` opens the VP50 secure session and sends one password unlock
  command.
- `mount` asks `udisksctl` to mount an unlocked filesystem partition.
- `ironkey_vp50_desktop_agent.py` can run in a desktop session and prompt with
  `kdialog` or `zenity` when a locked VP50 is plugged in.

The helper does not format, reset, repartition, or write to the decrypted
filesystem.

## Safety

IronKey devices usually have a limited number of password attempts. A wrong
unlock command may count as a failed password attempt. The tool therefore sends
only one unlock attempt per invocation and asks you to type `UNLOCK` unless
`--yes` is passed.

Use this only with devices you own or are authorized to access.

## Requirements

- Linux with SCSI generic support (`sg`).
- Python 3.10 or newer.
- `openssl` on `PATH` for AES-ECB encryption.
- `lsblk`, `udevadm`, and optionally `udisksctl`.
- `kdialog` or `zenity` for the desktop auto-unlock agent.
- Root privileges, or equivalent permissions to open the relevant `/dev/sg*`
  device.

## Usage

Show what Linux sees:

```bash
python3 ironkey_vp50.py status
```

Confirm sg access. The locked private LUN is often `/dev/sg0`, but check
`status` on your machine:

```bash
sudo python3 ironkey_vp50.py probe --sg /dev/sg0
```

Dry-run an unlock without sending anything:

```bash
sudo python3 ironkey_vp50.py unlock --sg /dev/sg0 --pvc --dry-run
```

Send one unlock attempt:

```bash
sudo python3 ironkey_vp50.py unlock --sg /dev/sg0 --pvc
```

By default the password is read with `getpass` and is not echoed. Avoid
`--password` on shared systems because command-line arguments can be visible to
other local users. GUI integrations should use `--password-stdin`.

After a successful unlock, inspect block devices:

```bash
python3 ironkey_vp50.py status
```

Mount read-only with udisksctl:

```bash
python3 ironkey_vp50.py mount --read-only
```

Unmount with your desktop environment or `udisksctl unmount -b /dev/sdXN`.

## Desktop Auto-Unlock

The desktop agent is a user-session process. When a locked VP50 appears, it:

1. shows a `kdialog` or `zenity` password prompt;
2. passes the password to `ironkey_vp50.py unlock --pvc --password-stdin`;
3. mounts the unlocked VP50 partition with `udisksctl`.

The password is not stored and is not placed in command-line arguments.

Install the integration:

```bash
sudo ./install-desktop.sh
```

The installer:

- installs command wrappers as `ironkey-vp50` and
  `ironkey-vp50-desktop-agent`;
- installs `ironkey-vp50-root-unlock`, a narrow root wrapper used only for the
  SG_IO data-out unlock path;
- installs a sudoers rule allowing the desktop user to run that root wrapper
  without a sudo password;
- installs the Python files under `/usr/local/lib/ironkey-vp50`;
- installs a udev `uaccess` rule for `0951:1576` sg devices;
- adds a freedesktop autostart entry for the desktop user that ran `sudo`.

After installing, unplug and replug the drive or log out and back in. You can
test the agent manually with:

```bash
ironkey-vp50-desktop-agent --once
```

`install-kde.sh` and `ironkey-vp50-kde-agent` remain compatibility aliases.
The installer writes a freedesktop autostart entry, so it is not strictly
KDE-only. It was tested on KDE Plasma. GNOME and other desktop environments
should work when they support freedesktop autostart, `sudo`, `udisksctl`, and
either `zenity` or `kdialog`, but they are not tested yet.

Packaged installs can run the setup command instead:

```bash
sudo ironkey-vp50-install-desktop
```

## Arch Packaging

An AUR package recipe is kept in `aur/ironkey-vp50-git`. The package installs
the command-line helper, desktop agent, udev metadata, and an opt-in setup
command. It does not write sudoers or per-user autostart files during package
installation; users run `sudo ironkey-vp50-install-desktop` for that.

## Password Derivation

The bundled macOS app's `DriveSDK::hashPassword` logic was recovered from the
binary. It keeps passwords shorter than 17 bytes as raw bytes padded to 16
bytes. Passwords of 17 bytes or longer are hashed using Qt
`QCryptographicHash::Algorithm` id `1`, which is MD5, yielding 16 bytes.

This behavior is implemented by `--password-mode vendor-auto`, the default.

## Recovered Flow

The VP50 unlock flow recovered from the app is:

1. Open the RSA secure session using the vendor app's built-in RSA key.
2. Derive the 16-byte session key from the host/device secret exchange.
3. Send `Start_Secure_Access` as:

```text
ff 8b 00 <domain> 03 00 00 00 00 00 00 00 00 00 00 00
```

4. Encrypt and send the built-in PVC0 key with `PVCFuncOpen`.
5. AES-ECB encrypt the 16-byte password material with the session key.
6. Send the protected login command:

```text
ff a4 00 <domain> <user> <time_interval> <auto_logout> 00 00 00 00 00 00 00 00 00
```

The password material is sent as a 16-byte data-out buffer. Defaults are
`domain=0`, `user=0`, `time_interval=0`, and `auto_logout=0`.

## License

MIT. See `LICENSE`.
