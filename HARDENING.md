# PyHSM Deployment Hardening Guide

This document provides concrete, step-by-step hardening instructions for
institutional deployments of PyHSM on Linux, Docker, and on-premises
infrastructure. Follow every section that applies to your environment.
Sections marked **REQUIRED** must be completed before a deployment is
considered production-ready.

---

## Table of Contents

1. [Operating System Requirements](#1-operating-system-requirements)
2. [Dedicated Service Account](#2-dedicated-service-account-required)
3. [File and Directory Permissions](#3-file-and-directory-permissions-required)
4. [Password Injection](#4-password-injection-required)
5. [Swap and Memory Protection](#5-swap-and-memory-protection-required)
6. [systemd Unit Hardening](#6-systemd-unit-hardening-recommended)
7. [Docker Hardening](#7-docker-hardening)
8. [Keystore Backup](#8-keystore-backup-required)
9. [Audit Log Protection](#9-audit-log-protection-required)
10. [Network Isolation](#10-network-isolation-recommended)
11. [Process Isolation Mode (IPC)](#11-process-isolation-mode-ipc-recommended)
12. [Dependency Verification](#12-dependency-verification-required)
13. [Operating System Hardening Checklist](#13-operating-system-hardening-checklist)

---

## 1. Operating System Requirements

- **Linux kernel ≥ 5.10** or **macOS ≥ 12**. Windows is supported for
  development only — do not run PyHSM in production on Windows.
- Python **3.11 or newer** from the official distribution (not a custom
  build with stripped security features).
- Encrypted filesystem or encrypted swap (see Section 5).
- NTP synchronized clock — key expiry (`expires_at`) depends on accurate
  system time.

---

## 2. Dedicated Service Account (REQUIRED)

Run PyHSM under a dedicated, unprivileged service account. Never run it
as `root`.

```bash
# Create a system account with no login shell and no home directory
useradd --system --no-create-home --shell /usr/sbin/nologin pyhsm

# Create the runtime directory
install -d -m 750 -o pyhsm -g pyhsm /var/lib/pyhsm
install -d -m 750 -o pyhsm -g pyhsm /run/pyhsm
install -d -m 750 -o pyhsm -g pyhsm /var/log/pyhsm
```

---

## 3. File and Directory Permissions (REQUIRED)

```bash
# Keystore file — readable only by the pyhsm user
install -m 600 -o pyhsm -g pyhsm /dev/null /var/lib/pyhsm/keystore.enc

# Audit log directory — writable only by pyhsm
chmod 750 /var/log/pyhsm
chown pyhsm:pyhsm /var/log/pyhsm

# Password file (see Section 4)
install -m 600 -o pyhsm -g pyhsm /dev/null /run/secrets/pyhsm-password

# IPC socket directory
chmod 700 /run/pyhsm
chown pyhsm:pyhsm /run/pyhsm
```

Verify with:

```bash
stat /var/lib/pyhsm/keystore.enc   # should show 0600 pyhsm pyhsm
stat /run/secrets/pyhsm-password   # should show 0600 pyhsm pyhsm
```

---

## 4. Password Injection (REQUIRED)

**Never** pass the master password via command-line argument or unguarded
environment variable. Use one of the following methods, in order of
preference:

### Method 1 — Password file (recommended)

```bash
# Write the password — no trailing newline, no shell history
printf '%s' 'YourStr0ng!Passphrase' > /run/secrets/pyhsm-password
chmod 600 /run/secrets/pyhsm-password
chown pyhsm:pyhsm /run/secrets/pyhsm-password

# Use with CLI
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    list

# Use with Python API
from hsm import PyHSM
hsm = PyHSM("/var/lib/pyhsm/keystore.enc",
            password_file="/run/secrets/pyhsm-password")
```

PyHSM enforces:
- File must be owned by the process effective UID
- File must have mode `0o600` (no group or world read)
- File must not be a symbolic link (TOCTOU protection via `O_NOFOLLOW`)

### Method 2 — Shamir M-of-N ceremony

For high-security deployments where no single person should hold the
complete password, split it into shares:

```bash
# At key ceremony: split a 32-byte random secret into 3-of-5 shares
python3 -c "import os; print(os.urandom(32).hex())" > /tmp/master-secret.hex
vectorguard-pyhsm split --threshold 3 --shares 5 \
    --secret "$(cat /tmp/master-secret.hex)" > /tmp/shares.json
shred -u /tmp/master-secret.hex
# Distribute one share to each custodian securely (printed, encrypted USB, etc.)
```

At runtime, collect threshold shares and reconstruct:

```bash
vectorguard-pyhsm reconstruct \
    --share '{"index":1,"data":"...","checksum":"..."}' \
    --share '{"index":3,"data":"...","checksum":"..."}' \
    --share '{"index":5,"data":"...","checksum":"..."}' \
    > /run/secrets/pyhsm-password
chmod 600 /run/secrets/pyhsm-password
```

### Method 3 — Environment variable (testing only)

```bash
export PYHSM_MASTER_PASSWORD="password"
export PYHSM_ALLOW_ENV_PASSWORD=1   # required acknowledgement
vectorguard-pyhsm ...
```

**Do not use in production.** The variable is visible in
`/proc/<pid>/environ` and may appear in shell history or CI/CD logs.

---

## 5. Swap and Memory Protection (REQUIRED)

PyHSM zeroizes key material immediately after use, but the operating
system may page memory contents to swap before zeroization. Mitigate this:

### Option A — Encrypted swap (recommended for bare metal)

```bash
# Debian/Ubuntu
apt-get install cryptsetup
# Add to /etc/crypttab:
# swap  /dev/sdXY  /dev/urandom  swap,cipher=aes-xts-plain64,size=256

# RHEL/Rocky
# Use system's built-in encrypted swap via /etc/crypttab
```

### Option B — Disable swap entirely (recommended for containers)

```bash
swapoff -a
# Remove swap entries from /etc/fstab to persist across reboots
sed -i '/swap/d' /etc/fstab
```

### Option C — RAM disk for secrets

Place the password file on a `tmpfs` mount so it never touches disk:

```bash
mount -t tmpfs -o size=1m,mode=700 tmpfs /run/secrets
printf '%s' 'YourPassword' > /run/secrets/pyhsm-password
chmod 600 /run/secrets/pyhsm-password
```

Add to `/etc/fstab` for persistence:
```
tmpfs  /run/secrets  tmpfs  defaults,size=1m,mode=700,noexec,nosuid  0 0
```

---

## 6. systemd Unit Hardening (Recommended)

Create `/etc/systemd/system/pyhsm.service`:

```ini
[Unit]
Description=PyHSM Key Management Service
Documentation=https://github.com/pavondunbar/PyHSM
After=network.target
Requires=network.target

[Service]
Type=simple
User=pyhsm
Group=pyhsm
ExecStart=/usr/local/bin/vectorguard-pyhsm-server \
    --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    --socket /run/pyhsm/pyhsm.sock
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Filesystem isolation
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pyhsm /run/pyhsm /var/log/pyhsm
ReadOnlyPaths=/run/secrets

# Privilege restrictions
NoNewPrivileges=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true

# Capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
LimitMEMLOCK=67108864

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pyhsm

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now pyhsm.service
systemctl status pyhsm.service
```

---

## 7. Docker Hardening

See also the reference `Dockerfile` and `docker-compose.yml` in the
repository root.

```bash
# Build
docker build -t pyhsm:2.1.0 .

# Run with hardening flags
docker run \
    --name pyhsm \
    --user pyhsm:pyhsm \
    --read-only \
    --tmpfs /tmp:noexec,nosuid,size=64m \
    --tmpfs /run/pyhsm:noexec,nosuid,size=1m \
    --security-opt no-new-privileges:true \
    --security-opt seccomp=./seccomp-pyhsm.json \
    --cap-drop ALL \
    --memory 512m \
    --pids-limit 64 \
    -v /var/lib/pyhsm:/data:Z \
    -v /run/secrets/pyhsm-password:/run/secrets/pyhsm-password:ro,Z \
    -v /var/log/pyhsm:/var/log/pyhsm:Z \
    pyhsm:2.1.0
```

Key flags explained:
- `--read-only` — root filesystem is read-only; only mounted volumes are writable
- `--cap-drop ALL` — no Linux capabilities; PyHSM requires none
- `--security-opt no-new-privileges` — prevents setuid escalation
- `--user pyhsm:pyhsm` — never run as root
- `-v .../pyhsm-password:ro` — password file mounted read-only

---

## 8. Keystore Backup (REQUIRED)

The keystore is a single encrypted file. Loss of this file means loss of
all keys. Implement a backup strategy before going to production.

```bash
# Create a backup using the built-in backup command
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    backup --dir /var/backups/pyhsm

# Verify a backup is readable
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    verify-backup /var/backups/pyhsm/pyhsm-backup-YYYYMMDDTHHMMSSZ.enc
```

Backup recommendations:
- Back up after every key rotation and key generation event
- Store backups on a separate physical host or offline media
- Test restore quarterly — a backup never tested is not a backup
- The backup file is encrypted with the same master password as the live
  keystore. Protect backup files with the same access controls.

---

## 9. Audit Log Protection (REQUIRED)

The HMAC-chained audit log is a security control. Protect it accordingly.

```bash
# Set permissions
chmod 640 /var/log/pyhsm/*.audit.jsonl
chown pyhsm:security /var/log/pyhsm/*.audit.jsonl

# Verify chain integrity
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    audit --verify

# Ship to SIEM (CEF format for Splunk/QRadar/ArcSight)
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    audit --siem-format cef | logger -t pyhsm -p security.info

# Ship as JSON for Elastic/OpenSearch
vectorguard-pyhsm --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    audit --siem-format json | curl -X POST \
        -H "Content-Type: application/json" \
        --data-binary @- \
        http://elastic:9200/pyhsm-audit/_doc
```

Use Linux audit framework (`auditd`) to detect tampering with the log file:

```bash
auditctl -w /var/log/pyhsm -p wxa -k pyhsm_audit
```

---

## 10. Network Isolation (Recommended)

If using IPC mode, the Unix socket should not be exposed to the network.

```bash
# Verify socket permissions
stat /run/pyhsm/pyhsm.sock  # should be 0600 owned by pyhsm

# Block outbound connections from the HSM process (except audit webhook if used)
# Using iptables owner match:
iptables -A OUTPUT -m owner --uid-owner pyhsm -j DROP

# Or via systemd's RestrictAddressFamilies=AF_UNIX (already in the unit above)
```

If PyHSM is wrapped in an API service, place it behind a reverse proxy
(nginx, Caddy) and restrict direct access to the Unix socket to the
application user only.

---

## 11. Process Isolation Mode (IPC) (Recommended)

Run PyHSM in a separate process to harden the trust boundary between
the HSM and your application code:

```bash
# Start the HSM server process
vectorguard-pyhsm-server \
    --store /var/lib/pyhsm/keystore.enc \
    --password-file /run/secrets/pyhsm-password \
    --socket /run/pyhsm/pyhsm.sock \
    --ipc-secret "$(cat /run/secrets/pyhsm-ipc-secret)" &

# In your application
from hsm.ipc_client import IPCClient

with IPCClient("/run/pyhsm/pyhsm.sock",
               ipc_secret=open("/run/secrets/pyhsm-ipc-secret").read().strip()) as hsm:
    ct = hsm.encrypt("my-key", "sensitive data")
```

With IPC mode, a compromised dependency in your application cannot
directly call `hsm.export_jwk()` or read `_master_password` — the HSM
lives in a different OS process with a different UID.

---

## 12. Dependency Verification (REQUIRED)

Always install from the hash-pinned lockfile:

```bash
pip install --require-hashes -r requirements.lock
```

Never run `pip install` without `--require-hashes` in production. Without
it, a compromised PyPI mirror can serve a modified `cryptography` package.

For Docker builds, the `Dockerfile` in this repository uses
`--require-hashes` by default.

---

## 13. Operating System Hardening Checklist

Before going live, verify each item:

```
[ ] PyHSM runs as a dedicated unprivileged user (not root)
[ ] Keystore file: chmod 600, owned by pyhsm user
[ ] Password file: chmod 600, owned by pyhsm user, on tmpfs
[ ] Audit log: chmod 640, shipped to SIEM or centralized log store
[ ] Swap encrypted or disabled
[ ] pip install uses --require-hashes -r requirements.lock
[ ] systemd unit has NoNewPrivileges=true, MemoryDenyWriteExecute=true
[ ] Backup exists and has been tested with verify-backup
[ ] Audit chain verified: vectorguard-pyhsm audit --verify returns OK
[ ] IPC mode enabled if application code is not fully trusted
[ ] NTP synchronized (clock skew can bypass key expiry)
[ ] SELinux or AppArmor policy applied (if available)
[ ] auditd rule watching keystore and audit log files for modification
```
