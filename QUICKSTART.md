# Quick Start

Get from zero to a report in about five minutes.

## 1. Install the required module

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

Optional (for Microsoft Defender alert signals):

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## 2. Run the analyzer

The simplest run — you'll be prompted for the affected user and admin account, then sign in interactively:

```powershell
.\SenderRestrictionAnalyzer.ps1
```

Or pass the values directly:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -AdminUPN admin@contoso.com
```

## 3. Sign in

A modern-authentication window opens for:

- **Exchange Online** and **Security & Compliance** (`ExchangeOnlineManagement`)
- **Microsoft Graph** (only if the optional module is installed) — consent to the requested read-only scopes

> Use a least-privilege account: **Security Reader** + **View-Only Recipients**. Global Admin is not required.

## 4. Wait for the two phases

```
========== PHASE 1: EXPORT LOGS ==========      ← collects evidence, writes CSVs + State.clixml, then disconnects
========== PHASE 2: GENERATE HTML REPORT ==========   ← offline verdict + report, no cloud calls
```

## 5. Open the report

When prompted:

```
Open report now? (Y/N)
```

Press **Y**. The report `RRLAnalysis_<user>_<timestamp>.html` opens in your browser.

---

## Common variations

Analyze a wider window (up to 90 days):

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -LookbackDays 30
```

Fastest run (skip per-recipient delivery detail):

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -SkipMessageTraceDetail
```

No Defender / Security & Compliance access:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -SkipDefender
```

Write output to a specific folder:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -OutputPath C:\temp\RRL
```

---

## What you get

| Verdict | Meaning |
|---------|---------|
| `EXPECTED_BLOCK_DAILY` | The daily recipient limit was reached. |
| `EXPECTED_BLOCK_HOURLY` | The hourly recipient limit was reached. |
| `EXPECTED_BLOCK` | Restricted, but no specific daily/hourly breach proven by the trace. |
| `NO_BLOCK_FOUND` | The user is not currently restricted. |

Plus CSV evidence files and a `State.clixml` snapshot for offline re-analysis. See [INSTRUCTIONS.md](INSTRUCTIONS.md) for full details.
