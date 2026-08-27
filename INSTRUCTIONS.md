# Instructions

Complete usage, permissions, and troubleshooting guide for `SenderRestrictionAnalyzer.ps1`.

---

## 1. Overview

Sender Restriction Analyzer diagnoses **outbound mail sending-limit blocks** in Exchange Online (Restricted Recipient List / RRL restrictions). It is an interactive, **read-only** troubleshooting tool for support engineers and administrators.

It runs in two phases:

1. **Phase 1 — Collect & Export (online):** Connects to Microsoft 365, gathers evidence, and writes per-dataset CSVs plus a `State.clixml` snapshot. Then it disconnects from all cloud services.
2. **Phase 2 — Analyze & Report (offline):** Re-reads the exported state, runs the deterministic verdict engine, and generates the HTML report with no further remote calls.

---

## 2. Prerequisites

### PowerShell
- Windows PowerShell 5.1 or later.

### Modules

```powershell
# Required
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Optional — enables Microsoft Defender for Office 365 alert signals
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

If `Microsoft.Graph.Authentication` is missing, the script still runs; Defender alert signals are simply unavailable.

### Permissions

Use a **least-privilege** account — Global Admin is **not** required:

- **Security Reader**
- **View-Only Recipients**

The script connects with interactive modern authentication (delegated permissions) to:

- **Exchange Online** — `Connect-ExchangeOnline`
- **Security & Compliance** — `Connect-IPPSSession`
- **Microsoft Graph** *(optional)* — `Connect-MgGraph` with scopes:
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `Directory.Read.All`
  - `AuditLog.Read.All`
  - `SecurityAlert.Read.All`

Access tokens are managed by the respective modules and are not stored in plain text by the script.

---

## 3. Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-AffectedUPN` | string | *(prompted)* | UPN of the affected sender being investigated. Validated against an email pattern. |
| `-AdminUPN` | string | *(current context / prompted)* | Admin UPN used to connect to Exchange Online and Security & Compliance. |
| `-OutputPath` | string | script directory | Directory for the report, CSVs, and state file. Must exist. |
| `-LookbackDays` | int (1–90) | `7` | Days of message-trace history to analyze. Capped at the `Get-MessageTraceV2` retention limit. |
| `-SkipDefender` | switch | off | Skip Defender / Security & Compliance collection (alerts and restricted entities). |
| `-SkipHistoricalSearch` | switch | off | Skip asynchronous historical search beyond 10 days (that search can add 5–30 minutes). |
| `-SkipMessageTraceDetail` | switch | off | Skip per-recipient delivery-detail lookups entirely (fastest). |
| `-MaxDetailLookups` | int (0–5000) | `200` | Maximum per-recipient delivery-detail lookups. Detail is only fetched for failed/blocked/spam-filtered rows. `0` = skip. |
| `-ParallelDetailLookups` | switch | off | Fan the delivery-detail lookups across a pool of Exchange Online runspaces. Falls back to serial automatically below a small threshold or if the pool cannot start. |
| `-DetailThrottleLimit` | int (2–8) | `4` | Number of parallel runspaces when `-ParallelDetailLookups` is set. Keep small to avoid throttling (429s). |

---

## 4. Usage Examples

Interactive (prompts for everything):

```powershell
.\SenderRestrictionAnalyzer.ps1
```

Specify the affected user and admin:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -AdminUPN admin@contoso.com
```

Analyze 30 days and write to a specific folder:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -LookbackDays 30 -OutputPath C:\temp\RRL
```

Without Defender / Security & Compliance:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -SkipDefender
```

Fastest run (summary rows only, no per-event timeline):

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -SkipMessageTraceDetail
```

Parallelize detail lookups on a large mailbox:

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -ParallelDetailLookups -DetailThrottleLimit 6
```

Verbose output (includes per-step timing summary):

```powershell
.\SenderRestrictionAnalyzer.ps1 -AffectedUPN user@contoso.com -Verbose
```

---

## 5. What the Script Collects

| Step | Data | Source |
|------|------|--------|
| 1 | Recipient validation (mailbox exists, type) | Exchange Online |
| 2 | Outbound spam policy limits (hourly/daily, internal/external) | Exchange Online |
| 3 | Message trace + per-recipient delivery detail; external/internal classification, hourly/daily aggregation | Exchange Online |
| 5 | Restricted-entity / blocked-sender status | Security & Compliance |
| 5.5 | SendAs / SendOnBehalf events | Unified audit log |
| 6 | Defender for Office 365 alerts (with MITRE techniques) | Microsoft Graph |
| 7 | Account health (forwarding, suspicious inbox rules) | Exchange Online |
| 7.5 | Supplemental identity and threat signals (expanded indicators) | Exchange Online / Graph |

---

## 6. Output Files

All files are written to `-OutputPath`, prefixed with the sanitized UPN and a run timestamp (`yyyyMMdd-HHmmss`).

| File | Description |
|------|-------------|
| `RRLAnalysis_<user>_<timestamp>.html` | Interactive report — open this. |
| `RRL_<user>_<timestamp>_MessageTrace.csv` | Message-trace rows; nested delivery detail serialized as a JSON column. |
| `RRL_<user>_<timestamp>_DailyStats.csv` | Per-day message/recipient aggregates. |
| `RRL_<user>_<timestamp>_StatusBreakdown.csv` | Delivery-status breakdown. |
| `RRL_<user>_<timestamp>_TopRecipientDomains.csv` | Top recipient domains. |
| `RRL_<user>_<timestamp>_RestrictedEntity.csv` | Restricted-entity status. |
| `RRL_<user>_<timestamp>_SendAsLogs.csv` | SendAs / SendOnBehalf audit events. |
| `RRL_<user>_<timestamp>_DefenderAlerts.csv` | Defender alerts with MITRE techniques. |
| `RRL_<user>_<timestamp>_SuspiciousInboxRules.csv` | Inbox rules flagged as security signals. |
| `RRL_<user>_<timestamp>_State.clixml` | Full-fidelity object snapshot used by Phase 2 and for offline re-analysis. |

> 🔒 **Confidential output:** These files contain UPNs, recipient addresses, message subjects, Message IDs, and security posture. Treat as confidential; review before sharing and do not email unencrypted.

### About `State.clixml`

`State.clixml` is a loss-free serialized snapshot of the collected evidence (preserving nested trace-detail timelines, real datetimes, and aggregations). Phase 2 re-hydrates it to build the report entirely offline. If it cannot be written, Phase 2 falls back to the in-memory data collected during the same run. It is also what enables re-generating the report later without reconnecting.

---

## 7. Understanding the Verdict

| Verdict | Meaning |
|---------|---------|
| `EXPECTED_BLOCK_DAILY` | The daily recipient limit was reached — the block is expected. |
| `EXPECTED_BLOCK_HOURLY` | The hourly recipient limit was reached — the block is expected. |
| `EXPECTED_BLOCK` | The user is restricted, but no specific daily/hourly breach was proven by the trace (e.g. message-rate limit, outbound spam, or malware detection). |
| `NO_BLOCK_FOUND` | The user is not currently restricted. |

### Report Tabs

- **Overview / Verdict** — classification, evidence lines, and policy-limit comparison (found vs. limit, per hour, internal/external).
- **Message Trace** — searchable, sortable, paged message rows plus daily stats, status breakdown, and top domains.
- **Mailbox Security Insights** — indicators evaluated with met/not-met status:
  - External forwarding configured
  - Inbox rules that forward/redirect/delete
  - Auto-forward to free webmail domains
  - Delegation or SendAs permissions
  - High similarity of message subjects
  - Active Defender alerts
  - Outbound messages quarantined
  - Unified audit logging enabled
- **Recommendations** — supported high-volume sending alternatives: High Volume Email (HVE) for Microsoft 365, Azure Communication Services Email, and dedicated bulk/marketing providers.

---

## 8. Troubleshooting

| Symptom | Cause / Resolution |
|---------|--------------------|
| `ExchangeOnlineManagement module is required but not installed` | Run `Install-Module ExchangeOnlineManagement`. |
| `Microsoft.Graph.Authentication module not found` (warning) | Optional. Install it to enable Defender alerts, or use `-SkipDefender`. |
| `Failed to connect to required services` | Verify the admin account, network access, and that MFA sign-in completed. |
| `Recipient validation failed` | Confirm the `-AffectedUPN` is a valid mailbox in this tenant. |
| Throttling / 429 errors during detail lookups | Lower `-DetailThrottleLimit`, or use `-SkipMessageTraceDetail`. Workers already retry with back-off. |
| Run is slow | Use `-SkipHistoricalSearch` and/or `-SkipMessageTraceDetail`; reduce `-LookbackDays`. |
| `State file unavailable; falling back to in-memory data` (warning) | Non-fatal — the report is still generated from in-memory data for this run. |
| Report won't open automatically | Open the `RRLAnalysis_*.html` file manually from `-OutputPath`. |

Add `-Verbose` to any run for detailed step logging and a per-step timing summary.

---

## 9. Security Notes

- **Read-only:** uses only `Get-*` / `Search-*` cmdlets — it never unblocks senders, changes policy, deletes rules, or submits messages. Remediation is guidance text only.
- Run with a least-privilege account (Security Reader + View-Only Recipients), not Global Admin.
- Dynamic values are HTML-escaped at render time to reduce XSS risk in the generated report; still review reports before sharing.
- All output (HTML/CSV/state) is **confidential** — it contains tenant configuration, UPNs, recipient addresses, message metadata, and security posture.

---

## Disclaimer

This script is provided "as is" without warranty of any kind. You are responsible for how you use it and for any outcomes resulting from its execution. The entire risk arising out of the use or performance of the script remains with you. The author and contributors are not liable for any damages resulting from its use.
