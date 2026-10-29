# Commercial License

PyHSM is open source software licensed under the GNU Affero General Public
License v3.0 (AGPL-3.0). See [LICENSE](LICENSE) for the full text.

---

## When You Need a Commercial License

You need a commercial license if any of the following apply:

- You are embedding PyHSM in a **proprietary product** you distribute to
  customers and you do not want to release your product's source code under
  AGPL.
- You are using PyHSM to provide a **network service** (SaaS, API, hosted
  application) and you do not want to release your application's complete
  source code under AGPL.
- Your organization's **legal policy** prohibits the use of AGPL-licensed
  software in commercial products or services.
- You require a written license agreement for **procurement, vendor
  onboarding, or compliance** purposes.

## When You Do Not Need a Commercial License

- Personal or hobby projects
- Open source projects whose code is released under AGPL-compatible terms
- Internal business use where you are not distributing software externally
  or providing a public-facing network service built on PyHSM
- Evaluation and proof-of-concept work

## Pricing

Commercial licenses are available on a **per-deployment** basis, billed
monthly or annually. Annual billing saves the equivalent of two months
(~17% discount).

| Tier | Deployments | Keys | Monthly | Annual |
|---|---|---|---|---|
| **Startup** | 1 production deployment | Up to 5 keys | $149/mo | $1,490/yr |
| **Growth** | Up to 5 deployments | Unlimited keys | $349/mo | $3,490/yr |
| **Scale** | Unlimited deployments | Unlimited keys | $749/mo | $7,490/yr |

All tiers include:
- Right to use PyHSM in proprietary products and services without AGPL
  obligations (no requirement to disclose your application source code)
- Written license agreement suitable for legal, procurement, and compliance
  review
- License coverage for the duration of the billing term (monthly or annual)
- A signed **license token** (RS256 JWT) for use with PyHSM's built-in
  license verification system (see below)

**Scale** additionally includes priority technical support with direct
access to the PyHSM engineering team.

## Contact

**pavon@vectorguardlabs.com**

Please include a brief description of your use case (product type, industry,
how you intend to deploy PyHSM, and your preferred billing term) so we can
get you set up quickly.

---

## How License Enforcement Works

As of v2.3.0, PyHSM includes **offline JWT license token verification**.
No network call is made at runtime — the token is self-contained and
verified locally using an embedded RSA public key.

### What Happens Without a Token

PyHSM runs normally under AGPL-3.0 open source terms. A notice is
printed to the log at startup:

```
No commercial license token provided — running under AGPL-3.0 terms.
Commercial use in proprietary products or SaaS requires a license.
```

### What Happens With a Valid Commercial Token

The token is verified at `PyHSM()` construction time. On success, the
session's `LicenseTier` and limits (max keys, max seats) are enforced
automatically. A `license_verified` event is written to the audit log.

### Using Your License Token

**Via the Python API:**

```python
from hsm import PyHSM

hsm = PyHSM(
    storage_path="keystore.enc",
    master_password="...",
    license_file="/etc/pyhsm/license.jwt",   # recommended
    # or: license_token="<jwt string>",
)
```

**Via the CLI (`--license-file` flag):**

```bash
vectorguard-pyhsm --license-file /etc/pyhsm/license.jwt license
vectorguard-pyhsm --license-file /etc/pyhsm/license.jwt generate my-key
```

**Via environment variable:**

```bash
export PYHSM_LICENSE_TOKEN="<jwt string>"
vectorguard-pyhsm generate my-key
```

The `PYHSM_LICENSE_TOKEN` variable is cleared from the process
environment immediately after it is read.

### Checking Your Active License

```bash
vectorguard-pyhsm --license-file /etc/pyhsm/license.jwt license
```

Output:

```
License type : Commercial
Tier         : Growth
Licensee     : you@example.com
Expires      : 2027-10-29T17:55:43+00:00  (364 days remaining)
Max keys     : unlimited
Max seats    : 5
Token ID     : 7bb6351d-afe2-4c7d-bd7f-1565165aca79
```

### Token Properties

| Property | Value |
|---|---|
| Algorithm | RS256 (RSA-2048 + SHA-256, PKCS#1 v1.5) |
| Verification | Offline — embedded public key, no network call |
| Expiry | Configurable per token (recommended: 90 days) |
| Revocation | Tokens expire naturally; renewal is via a new token |
| Air-gap safe | Yes — no outbound connection required |

### Tier Limits Enforced at Runtime

| Tier | Max Keys per Instance |
|---|---|
| Startup | 5 |
| Growth | Unlimited |
| Scale | Unlimited |

Attempting to create a key beyond the tier's limit raises a
`LicenseError` with a message directing you to upgrade.
