# MCP Certification Readiness Checker

## A Companion Lab for The Workbench

Everything on **Microsoft MCP server certification overview (preview)** that a machine can
check, checked by a machine, before you spend a submission cycle finding out in Partner
Center.

Companion to the post *Your MCP Server Now Needs a Key Vault* on
[The Workbench](https://www.theworkbench.blog).

Source of truth for every rule in here:
<https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-certification>

---

## Why

The certification page changed in late September 2026. The manifest moved to the **v1.30**
Teams schema, **Azure Key Vault** authentication configuration became mandatory on every
submission, and the legacy certification path closes on **October 31, 2026**. Most of what
the page asks for is mechanically verifiable: a schema version, a file that exists, a URI
of the right shape, a secret named with the right capital letters. None of that deserves a
round trip through automated validation.

---

## What It Checks

| Area | Check |
|---|---|
| Package | manifest present and parses, intro file present, `Known issues` section |
| Schema | `$schema` on v1.30, `manifestVersion` gone, `version` is `1.30` |
| Metadata | every required field populated, and no `<PLACEHOLDER>` left behind |
| Icons | outline and color exist, are real PNGs, dimensions reported |
| Connector | `mcpServerUrl` present and https, tool file declared and on disk and valid JSON |
| Connector | `authorization.type` is `AzureKeyVault` |
| Connector | `referenceId` is a **vault URI**, and explicitly not a secret URI |
| ASCII | manifest and tool file are ASCII only, offender reported by line and column |
| Vault | vault reachable, RBAC authorization on, not legacy access policies |
| Secrets | required secret set for your identity provider, matched **case sensitively** |
| RBAC | certification service principal exists and holds a Key Vault read role |

Two notes on deliberate restraint. Icon **dimensions are reported, not asserted**, because
Teams package guidance governs the exact sizes and that guidance lives outside this
article. And the **intro file is a warning, not a failure**, because the page contradicts
itself: the *What's changing* table calls `intro.md` required while the section below it is
headed *Intro file (Optional)*. Include it anyway.

---

## Repo Structure

```
mcp-cert-lab/
├── README.md                        # This file
├── Test-McpCertReadiness.ps1        # The checker
├── samples/
│   ├── good-package/                # A package that passes cleanly
│   │   ├── manifest.json            # v1.30, vault URI, every field populated
│   │   ├── mcptools.json            # Three tools, JSON Schema inputs
│   │   ├── intro.md                 # With a Known issues and limitations section
│   │   ├── Color.png                # 192x192
│   │   └── Outline.png              # 32x32
│   └── bad-package/                 # Eight planted defects, one file
│       └── manifest.json            # devPreview schema, secret URI, smart quote, ...
└── tests/
    └── Invoke-Tests.ps1             # Asserts good passes AND bad is caught, by name
```

---

## Prerequisites

- **PowerShell 7** or later
- **Az.KeyVault** and **Az.Resources**, only if you pass `-CheckVault`
- A `Connect-AzAccount` session, same condition

The package checks run with no Azure connection at all. That is the point: most of what
fails a submission fails on disk.

---

## Running It

Check a package:

```powershell
./Test-McpCertReadiness.ps1 -PackagePath ./samples/good-package
```

Check a package and the live vault behind it:

```powershell
Connect-AzAccount
./Test-McpCertReadiness.ps1 -PackagePath ./my-package -IdentityProvider AzureAD -CheckVault
```

The vault name is derived from the manifest's `referenceId`, so you normally do not pass
`-VaultName`. Exit code is **0** when nothing failed and **1** when anything did, which
makes it a usable gate in a pipeline.

`-IdentityProvider` selects which secret set is required, per the article's table:

| Value | Required secrets |
|---|---|
| `OAuth2` | `ClientId`, `ClientSecret`, `AuthorizationUrl`, `TokenUrl` |
| `OAuth2Refresh` | the above plus `RefreshUrl` |
| `OAuth2Scopes` | the OAuth2 set plus `Scopes` |
| `AzureAD` | `ClientId`, `ClientSecret`, `TokenUrl`, `AzureActiveDirectoryResourceId` |

---

## Running the Tests

```powershell
./tests/Invoke-Tests.ps1
```

The suite runs both sample packages and asserts the good one exits clean **and** that each
of the eight planted defects in the bad one is named in the output. A checker that only
ever says "pass" is worse than no checker, so the tests are written to catch a check
quietly regressing to always-pass. Break the secret-URI comparison on purpose and
`detects: secret URI in referenceId` goes red, which is exactly what you want from a
safety net.

---

## Provisioning the Vault

The article documents Key Vault setup as a portal exercise. The blog post carries the Az
PowerShell equivalent: resource group, vault, the three required secrets, a service
principal for Microsoft's certification application
`8e91e74f-afe9-41cd-8c3f-17a9562a74ea`, and a `Key Vault Secrets User` role assignment
scoped to the vault.

One trap worth repeating here. Do not reach for `New-AzKeyVault -EnableRbacAuthorization`.
That parameter was removed in **Az 12.0.0**, replaced by `-DisableRbacAuthorization`, and
RBAC is now the default. The trap that survives is reusing an **existing** vault built on
legacy access policies, where an RBAC role assignment looks like it succeeded and grants
nothing. This checker flags exactly that case under `RBAC authorization enabled`.

---

## Not Covered

Honest scope. These are review criteria, not package rules, and no script can stand in for
them:

- Functional and safety review of the server's actual runtime behavior
- Publisher eligibility and Partner Center business verification
- Whether your tool descriptions are good enough for a model to choose correctly
- Teams icon safe-area, contrast and branding compliance

---

**MG.-**
Mariano Gomez Bent
Former Microsoft BizApps MVP
