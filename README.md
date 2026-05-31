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
other local users.

After a successful unlock, inspect block devices:

```bash
python3 ironkey_vp50.py status
```

Mount read-only with udisksctl:

```bash
python3 ironkey_vp50.py mount --read-only
```

Unmount with your desktop environment or `udisksctl unmount -b /dev/sdXN`.

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
