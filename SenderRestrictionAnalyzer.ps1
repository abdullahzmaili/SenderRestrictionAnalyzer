<#
.SYNOPSIS
    Diagnoses and reports on outbound mail sending-limit blocks in Exchange Online.

.DESCRIPTION
    Sender Restriction Analyzer is an interactive troubleshooting tool that helps support
    engineers and customers investigate outbound mail sending-limit.
    
    The tool collects evidence from Exchange Online, Security & Compliance, and optionally
    Microsoft Graph, applies a deterministic verdict engine to classify the restriction,
    and generates a comprehensive interactive HTML report.
    
    Key capabilities:
    - Validates affected user mailbox
    - Collects message trace evidence with external/internal recipient classification
    - Analyzes outbound spam policy limits
    - Checks restricted entity status
    - Produces verdict: EXPECTED_BLOCK_DAILY, EXPECTED_BLOCK_HOURLY, EXPECTED_BLOCK, or NO_BLOCK_FOUND
    - Generates evidence and facts for Microsoft Support
    - Creates self-contained interactive HTML report with charts and filtering
    - Two-phase run: Phase 1 exports evidence to CSVs; Phase 2 builds the report offline

.NOTES
    Tool Name      : Sender Restriction Analyzer
    File Name      : SenderRestrictionAnalyzer.ps1
    Author         : Abdullah Zmaili
    Version        : 1.0
    Date Created   : 2026-August-27
    Date Updated   : 2026-August-27
    Prerequisite   : PowerShell 5.1 or later, Administrator privileges for some checks

    SECURITY NOTES:
    - This script connects with interactive modern authentication (delegated admin permissions)
      using ExchangeOnlineManagement (Connect-ExchangeOnline and Connect-IPPSSession) and,
      optionally, Microsoft.Graph.Authentication (Connect-MgGraph) for Defender alerts.
    - Access tokens are managed by the ExchangeOnlineManagement and Microsoft Graph modules and
      are not stored in plain text by this script.
    - For automated/service scenarios, consider using certificate-based app-only authentication
      (or a Managed Identity where supported) instead of interactive sign-in.
    - Most dynamic values are HTML-escaped at render time by the report's JavaScript esc() helper
      to reduce XSS risk in the generated reports; however, review reports before sharing.
    - Review and audit exported CSV/HTML files before sharing - they may contain sensitive
      tenant configuration data.

    - READ-ONLY Script: uses only Get-*/Search-* cmdlets; it never unblocks senders, changes policy, deletes rules, or submits messages (remediation appears as guidance text only). 
    - Run with a least-privilege account (Security Reader + View-Only Recipients), NOT Global Admin. 
    - Requires the ExchangeOnlineManagement module; Microsoft.Graph.Authentication is optional for Defender alert signals.
    - All output (HTML/CSV/state) is CONFIDENTIAL - it contains UPNs, recipient addresses, message metadata, and security posture. 


.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed
    successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption,
       or other losses, even if warned of the risks.

.PARAMETER AffectedUPN
    The User Principal Name (UPN) of the affected sender whose outbound mail is blocked or restricted.
    Example: john.doe@contoso.com
    If not provided, you will be prompted interactively.

.PARAMETER AdminUPN
    Admin User Principal Name (UPN) for connecting to Exchange Online and Security & Compliance PowerShell.
    Example: admin@contoso.com
    If not provided, the current context will be used or you will be prompted.

.PARAMETER OutputPath
    Directory path for the generated HTML report. Defaults to the script's directory.
    The report filename will be: RRLAnalysis_<upn-localpart>_<yyyyMMdd-HHmmss>.html

.PARAMETER LookbackDays
    Number of days to look back for message trace evidence. Defaults to 7 days.
    Valid range: 1-90 days (capped at the Get-MessageTraceV2 retention limit).

.PARAMETER SkipDefender
    Skip Defender for Office 365 and Security & Compliance data collection.
    Use when you don't have Security Reader permissions or when Defender signals are not needed.

.PARAMETER SkipHistoricalSearch
    Skip historical search beyond 10 days. Enabled by default.
    Historical search is asynchronous and adds 5-30 minutes to the run.
    RRL blocks are typically driven by recent spikes, so 10-day real-time trace is usually sufficient.

.PARAMETER SkipMessageTraceDetail
    Skip per-recipient delivery-detail lookups (Get-MessageTraceDetailV2) entirely.
    Fastest option; the report still shows message-trace summary rows but no per-event timeline.

.PARAMETER MaxDetailLookups
    Maximum number of per-recipient delivery-detail lookups to perform. Defaults to 200.
    Detail is only fetched for failed/blocked/spam-filtered rows (the ones relevant to RRL),
    so this cap is rarely reached. Set to 0 to skip detail lookups (same as -SkipMessageTraceDetail).

.PARAMETER ParallelDetailLookups
    Opt-in. Fan the per-recipient delivery-detail lookups (Get-MessageTraceDetailV2) across a
    pool of Exchange Online runspaces instead of calling them serially. Each worker opens its
    own Connect-ExchangeOnline session (cached-token reuse), so this only pays off when many
    detail calls remain after filtering; below a small amortization threshold the serial path
    is used automatically. If the pool cannot start, it silently falls back to serial.

.PARAMETER DetailThrottleLimit
    Number of parallel Exchange Online runspaces to use when -ParallelDetailLookups is set.
    Defaults to 4 (range 2-8). Keep this small to avoid Exchange throttling (429s), which the
    workers already retry with Retry-After / exponential back-off.

.EXAMPLE
    .\RRLAnalyzer.ps1
    Runs interactively, prompting for UPN and admin account.

.EXAMPLE
    .\RRLAnalyzer.ps1 -AffectedUPN john.doe@contoso.com
    Analyzes the specified user, prompting for admin UPN.

.EXAMPLE
    .\RRLAnalyzer.ps1 -AffectedUPN john.doe@contoso.com -SkipDefender
    Analyzes without connecting to Defender/Security & Compliance (skips alerts and restricted entities).

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$AffectedUPN,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$AdminUPN,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ if ([string]::IsNullOrWhiteSpace($_)) { $true } else { Test-Path $_ -PathType Container } })]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$LookbackDays = 7,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDefender,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHistoricalSearch,

    [Parameter(Mandatory = $false)]
    [switch]$SkipMessageTraceDetail,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 5000)]
    [int]$MaxDetailLookups = 200,

    [Parameter(Mandatory = $false)]
    [switch]$ParallelDetailLookups,

    [Parameter(Mandatory = $false)]
    [ValidateRange(2, 8)]
    [int]$DetailThrottleLimit = 4
)

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

#region Configuration

# RRL Thresholds and Defaults
# ⚠ VERIFY: These default values should be confirmed against current Microsoft documentation
# and the tenant's live configuration. Actual limits may vary by license SKU (E1/E3/E5).
$script:RrlThresholds = @{
    # Default RRL cap (external recipients per day)
    DefaultRrlDailyLimit = 10000  # ⚠ VERIFY - commonly cited, may vary by SKU
    
    # Outbound spam policy defaults (if policy returns 0 or null, use these)
    DefaultExternalPerHour = 500   # ⚠ VERIFY
    DefaultInternalPerHour = 1000  # ⚠ VERIFY
    DefaultPerDay = 1000           # ⚠ VERIFY - often lower than RRL cap
    
    # Burst detection (rolling window)
    BurstWindowMinutes = 60        # Rolling window for hourly burst detection

    # Exact subject repeated across message-trace recipient rows
    SubjectSimilarityThreshold = 0.50
}

#endregion

#region Helper Functions

#region Write-ProgressHelper
function Write-ProgressHelper {
    <#
    .SYNOPSIS
        Wrapper for Write-Progress with consistent activity naming.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$Status = '',
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory = $false)]
        [switch]$Completed
    )
    
    $activity = "Sender Restriction Analysis: $AffectedUPN"
    
    if ($Completed) {
        Write-Progress -Activity $activity -Completed
    }
    elseif ($PercentComplete -ge 0) {
        Write-Progress -Activity $activity -Status $Status -PercentComplete $PercentComplete
    }
    else {
        Write-Progress -Activity $activity -Status $Status
    }
}
#endregion

#region ConvertTo-RrlRows
function ConvertTo-RrlRows {
    <#
    .SYNOPSIS
        Projects source objects into ordered PSCustomObjects from a compact spec, applying the
        report's standard coercions. Each spec entry is @('outName','InName'[,'type']) where type
        is string (default), int, bool, date, or raw.
    #>
    param(
        $Source,
        [Parameter(Mandatory = $true)][object[]]$Map
    )
    @($Source | ForEach-Object {
        $src = $_
        $row = [ordered]@{}
        foreach ($m in $Map) {
            $out = $m[0]; $in = $m[1]; $type = if ($m.Count -ge 3) { $m[2] } else { 'string' }
            $v = $src.$in
            switch ($type) {
                'int'  { $row[$out] = [int]$v }
                'bool' { $row[$out] = [bool]$v }
                'date' { $row[$out] = if ($v) { try { ([datetime]$v).ToString('yyyy-MM-dd HH:mm:ss') } catch { [string]$v } } else { '' } }
                'raw'  { $row[$out] = $v }
                default { $row[$out] = [string]$v }
            }
        }
        [PSCustomObject]$row
    })
}
#endregion

#region New-RrlResult
function New-RrlResult {
    <#
    .SYNOPSIS
        Builds a standard result object. Success defaults to $true; -Extra adds/overrides fields.
    #>
    param([bool]$Success = $true, [string]$ErrorMessage = $null, $Extra)
    $o = [ordered]@{ Success = $Success; Error = $ErrorMessage }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    [PSCustomObject]$o
}
#endregion

#region New-RrlError
function New-RrlError {
    <#
    .SYNOPSIS
        Shorthand for a failure result (Success = $false) with an optional -Extra field set.
    #>
    param([Parameter(Mandatory = $true)][string]$ErrorMessage, $Extra)
    New-RrlResult -Success $false -ErrorMessage $ErrorMessage -Extra $Extra
}
#endregion

#region New-RrlIndicator
function New-RrlIndicator {
    <#
    .SYNOPSIS
        Builds a Security Signal object. Entries/Messages are added only when supplied.
    #>
    param(
        [string]$Name, [string]$Condition, [bool]$Met, [string]$Detail, [string]$DetailType,
        $Entries, $Messages
    )
    $o = [ordered]@{ Name = $Name; Condition = $Condition; Met = $Met; Detail = $Detail; DetailType = $DetailType }
    if ($PSBoundParameters.ContainsKey('Entries')) { $o.Entries = $Entries }
    if ($PSBoundParameters.ContainsKey('Messages')) { $o.Messages = $Messages }
    [PSCustomObject]$o
}
#endregion

#endregion

#region Connection Management

#region Connect-RrlServices
function Connect-RrlServices {
    <#
    .SYNOPSIS
        Connects to Exchange Online and optionally Security & Compliance and Microsoft Graph.
        Reuses existing sessions where possible.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AdminUpn,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipDefender,
        
        [Parameter(Mandatory = $false)]
        [switch]$ConnectGraph
    )
    
    try {
        # Check for existing Exchange Online session
        $existingEXO = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if (-not $existingEXO) {
            Write-Information -MessageData "[INFO] Connecting to Exchange Online..." -InformationAction Continue
            if ($AdminUpn) {
                Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false -ErrorAction Stop
            }
            else {
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            }
            Write-Information -MessageData "[INFO] ✓ Connected to Exchange Online" -InformationAction Continue
        }
        else {
            Write-Verbose "Reusing existing Exchange Online session"
        }
        
        # Connect to Security & Compliance (IPPS) unless -SkipDefender
        if (-not $SkipDefender) {
            $existingIPPS = Get-PSSession | Where-Object {
                $_.ConfigurationName -eq 'Microsoft.Exchange' -and
                $_.ComputerName -like '*compliance*' -and
                $_.State -eq 'Opened'
            }
            
            if (-not $existingIPPS) {
                Write-Information -MessageData "[INFO] Connecting to Security and Compliance..." -InformationAction Continue
                if ($AdminUpn) {
                    Connect-IPPSSession -UserPrincipalName $AdminUpn -ShowBanner:$false -ErrorAction Stop
                }
                else {
                    Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
                }
                Write-Information -MessageData "[INFO] ✓ Connected to Security and Compliance" -InformationAction Continue
            }
            else {
                Write-Verbose "Reusing existing Security and Compliance session"
            }
        }
        
        # Optional: Connect to Microsoft Graph for supplemental identity and threat signals
        if ($ConnectGraph) {
            try {
                $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                $requiredScopes = @('User.Read.All', 'UserAuthenticationMethod.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'SecurityAlert.Read.All')
                if (-not $graphContext) {
                    Write-Information -MessageData "[INFO] Connecting to Microsoft Graph..." -InformationAction Continue
                    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
                    Write-Information -MessageData "[INFO] ✓ Connected to Microsoft Graph" -InformationAction Continue
                }
                elseif (($requiredScopes | Where-Object { $graphContext.Scopes -notcontains $_ })) {
                    # Existing session is missing one or more required scopes (e.g. SecurityAlert.Read.All) — reconnect to consent.
                    Write-Information -MessageData "[INFO] Reconnecting to Microsoft Graph for additional permissions..." -InformationAction Continue
                    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
                    Write-Information -MessageData "[INFO] ✓ Connected to Microsoft Graph" -InformationAction Continue
                }
                else {
                    Write-Verbose "Reusing existing Microsoft Graph session"
                }
            }
            catch {
                Write-Warning "Failed to connect to Microsoft Graph (some supplemental signals will be unavailable): $_"
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to connect to required services: $_"
        return $false
    }
}
#endregion

#region Disconnect-RrlServices
function Disconnect-RrlServices {
    <#
    .SYNOPSIS
        Disconnects from all RRL analysis services.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Disconnect Exchange Online
        $exoSessions = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($exoSessions) {
            Write-Verbose "Disconnecting from Exchange Online..."
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        # Disconnect Microsoft Graph
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($graphContext) {
            Write-Verbose "Disconnecting from Microsoft Graph..."
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Error during disconnect: $_"
    }
}
#endregion

#endregion

#region Data Collection Functions

#region Get-RrlRecipientValidation
function Get-RrlRecipientValidation {
    <#
    .SYNOPSIS
        Validates that the affected user exists and retrieves mailbox details.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn
    )
    
    try {
        Write-ProgressHelper -Status "Validating recipient: $Upn..." -PercentComplete 5
        
        $recipient = Get-Recipient -Identity $Upn -ErrorAction SilentlyContinue
        if (-not $recipient) {
            return New-RrlError "Recipient not found: $Upn" ([ordered]@{ Exists = $false })
        }
        
        $mailbox = $null
        if ($recipient.RecipientTypeDetails -like '*Mailbox*') {
            $mailbox = Get-EXOMailbox -Identity $Upn -Properties RecipientTypeDetails, DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward -ErrorAction SilentlyContinue
        }
        
        return [PSCustomObject]@{
            Success = $true
            Error = $null
            Exists = $true
            RecipientType = $recipient.RecipientType
            RecipientTypeDetails = $recipient.RecipientTypeDetails
            DisplayName = $recipient.DisplayName
            PrimarySmtpAddress = $recipient.PrimarySmtpAddress
            MailboxObject = $mailbox
        }
    }
    catch {
        return New-RrlError "Error validating recipient: $_" ([ordered]@{ Exists = $false })
    }
}
#endregion

#region Get-RrlOutboundSpamPolicy
function Get-RrlOutboundSpamPolicy {
    <#
    .SYNOPSIS
        Retrieves outbound spam policy limits and enforcement action.
        Resolves which policy applies to the user via rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn
    )
    
    try {
        Write-ProgressHelper -Status "Retrieving outbound spam policy..." -PercentComplete 10
        
        # Get all policies and rules
        $policies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $rules = Get-HostedOutboundSpamFilterRule -ErrorAction Stop
        
        # Find which policy applies to this user
        $applicableRule = $rules | Where-Object {
            $_.State -eq 'Enabled' -and (
                $null -eq $_.SentTo -or $_.SentTo.Count -eq 0 -or
                $_.SentTo -contains $Upn -or
                ($_.SentTo | Where-Object { $Upn -like "*@$_" })
            )
        } | Sort-Object Priority | Select-Object -First 1
        
        if ($applicableRule) {
            $policy = $policies | Where-Object { $_.Identity -eq $applicableRule.HostedOutboundSpamFilterPolicy }
        }
        else {
            # Default policy
            $policy = $policies | Where-Object { $_.Name -eq 'Default' } | Select-Object -First 1
        }
        
        if (-not $policy) {
            return New-RrlError "Could not retrieve outbound spam policy"
        }
        
        return [PSCustomObject]@{
            Success = $true
            Error = $null
            PolicyName = $policy.Name
            RecipientLimitExternalPerHour = if ($policy.RecipientLimitExternalPerHour -eq 0) { $script:RrlThresholds.DefaultExternalPerHour } else { $policy.RecipientLimitExternalPerHour }
            RecipientLimitInternalPerHour = if ($policy.RecipientLimitInternalPerHour -eq 0) { $script:RrlThresholds.DefaultInternalPerHour } else { $policy.RecipientLimitInternalPerHour }
            RecipientLimitPerDay = if ($policy.RecipientLimitPerDay -eq 0) { $script:RrlThresholds.DefaultPerDay } else { $policy.RecipientLimitPerDay }
            ActionWhenThresholdReached = $policy.ActionWhenThresholdReached
            AutoForwardingMode = $policy.AutoForwardingMode
            AppliedViaRule = if ($applicableRule) { $applicableRule.Name } else { 'Default' }
        }
    }
    catch {
        return New-RrlError "Error retrieving outbound spam policy: $_"
    }
}
#endregion

#region Get-RrlDetailEvents
function Get-RrlDetailEvents {
    <#
    .SYNOPSIS
        Retrieves and normalizes the per-recipient delivery-detail events for a single
        message/recipient via Get-MessageTraceDetailV2, with 429/Retry-After back-off.
        Always returns an array (empty on failure) so callers stay best-effort.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MessageTraceId,
        [Parameter(Mandatory = $true)][string]$RecipientAddress,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3
    )
    $attempt = 0
    while ($true) {
        try {
            $detailEvents = Get-MessageTraceDetailV2 -MessageTraceId $MessageTraceId -RecipientAddress $RecipientAddress -ErrorAction Stop
            if ($detailEvents) {
                return @($detailEvents | ForEach-Object {
                    [PSCustomObject]@{
                        Date   = if ($_.Date -is [datetime]) { $_.Date.ToString('yyyy-MM-dd HH:mm:ss') } else { [string]$_.Date }
                        Event  = [string]$_.Event
                        Detail = [string]$_.Detail
                    }
                })
            }
            return @()
        }
        catch {
            $msg = "$($_.Exception.Message)"
            $throttled = $msg -match '(?i)429|throttl|too many request|temporarily unavailable|server side error'
            if ($throttled -and $attempt -lt $MaxRetries) {
                $retryAfter = $null
                try { $retryAfter = $_.Exception.Response.Headers['Retry-After'] } catch { }
                $delay = if ($retryAfter -and ([int]::TryParse("$retryAfter", [ref]([int]$null)))) { [int]$retryAfter } else { [int][math]::Pow(2, $attempt + 1) }
                Start-Sleep -Seconds ([Math]::Min($delay, 30))
                $attempt++
                continue
            }
            Write-Verbose "Detail lookup failed for $RecipientAddress (attempt $attempt): $msg"
            return @()
        }
    }
}
#endregion

#region Get-RrlDetailEventsBatch
function Get-RrlDetailEventsBatch {
    <#
    .SYNOPSIS
        Fans per-recipient delivery-detail lookups across a pool of Exchange Online runspaces.
        Each runspace opens its own Connect-ExchangeOnline session (cached-token reuse), processes
        a round-robin chunk of the targets with 429 back-off, and returns a key -> events hashtable.
        Results are merged and returned as one hashtable keyed by "MessageTraceId|RecipientAddress".
        Returns $null on catastrophic failure so the caller can fall back to the serial path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Targets,
        [Parameter(Mandatory = $false)][string]$AdminUpn,
        [Parameter(Mandatory = $false)][int]$ThrottleLimit = 4,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 900,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3
    )

    $targetList = @($Targets)
    if ($targetList.Count -eq 0) { return @{} }

    # Round-robin partition into up to $ThrottleLimit chunks for balanced load.
    $chunkCount = [Math]::Min($ThrottleLimit, $targetList.Count)
    $chunks = @(for ($i = 0; $i -lt $chunkCount; $i++) { , ([System.Collections.Generic.List[object]]::new()) })
    for ($i = 0; $i -lt $targetList.Count; $i++) { $chunks[$i % $chunkCount].Add($targetList[$i]) }

    # Worker runs in a fresh runspace, so inject Get-RrlDetailEvents (the serial path's
    # fetch/normalize/retry) rather than duplicating its body here.
    $detailFuncDef = "function Get-RrlDetailEvents {`n" + (Get-Command Get-RrlDetailEvents).Definition + "`n}"
    $workerText = @'
param($chunk, $adminUpn, $maxRetries, $detailFuncDef)
$result = @{}
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if ($adminUpn) { Connect-ExchangeOnline -UserPrincipalName $adminUpn -ShowBanner:$false -ErrorAction Stop }
    else { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
    . ([ScriptBlock]::Create($detailFuncDef))
    foreach ($t in $chunk) {
        $result[$t.Key] = @(Get-RrlDetailEvents -MessageTraceId $t.MessageTraceId -RecipientAddress $t.RecipientAddress -MaxRetries $maxRetries)
    }
}
finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}
return $result
'@

    $instances = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($chunk in $chunks) {
            $ps = [PowerShell]::Create()
            [void]$ps.AddScript($workerText)
            [void]$ps.AddArgument($chunk)
            [void]$ps.AddArgument($AdminUpn)
            [void]$ps.AddArgument($MaxRetries)
            [void]$ps.AddArgument($detailFuncDef)
            $async = $ps.BeginInvoke()
            $instances.Add([PSCustomObject]@{ PS = $ps; Async = $async })
        }

        $merged = @{}
        foreach ($inst in $instances) {
            $done = $inst.Async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)
            if ($done) {
                $res = $inst.PS.EndInvoke($inst.Async)
                foreach ($r in @($res)) {
                    if ($r -is [System.Collections.IDictionary]) {
                        foreach ($k in $r.Keys) { $merged[$k] = $r[$k] }
                    }
                }
            }
            else {
                Write-Verbose "A detail-lookup runspace timed out after ${TimeoutSeconds}s."
            }
        }
        return $merged
    }
    finally {
        foreach ($inst in $instances) { try { $inst.PS.Dispose() } catch { } }
    }
}
#endregion

#region Get-RrlMessageTrace
function Get-RrlMessageTrace {
    <#
    .SYNOPSIS
        Retrieves message trace data for the affected user with pagination.
        Classifies external vs internal recipients and aggregates hourly/daily patterns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,
        
        [Parameter(Mandatory = $true)]
        [int]$LookbackDays,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipMessageTraceDetail,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDetailLookups = 200,
        
        [Parameter(Mandatory = $false)]
        [switch]$ParallelDetailLookups,
        
        [Parameter(Mandatory = $false)]
        [int]$DetailThrottleLimit = 4,
        
        [Parameter(Mandatory = $false)]
        [string]$AdminUpn
    )
    
    try {
        Write-ProgressHelper -Status "Retrieving message trace data (last $LookbackDays days)..." -PercentComplete 20
        
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$LookbackDays)
        
        # Get accepted domains for external classification (cached for the process lifetime).
        if (-not $script:RrlAcceptedDomains) {
            $script:RrlAcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | Select-Object -ExpandProperty DomainName)
        }
        $acceptedDomains = $script:RrlAcceptedDomains
        
        # Paginated message trace retrieval (Get-MessageTraceV2 replaces the deprecated Get-MessageTrace).
        # Get-MessageTraceV2 allows at most a 10-day interval per query, so split the requested
        # lookback into <=10-day windows and page within each. V2 has no -Page/-PageSize; page by
        # narrowing -EndDate to the last record's Received and passing -StartingRecipientAddress to
        # continue past the boundary without duplicates.
        $allMessages = [System.Collections.Generic.List[object]]::new()
        $pageSize = 5000
        $maxWindowDays = 10
        $seenKeys = [System.Collections.Generic.HashSet[string]]::new()
        $pageNum = 1

        $windowEnd = $endDate
        while ($windowEnd -gt $startDate) {
            $windowStart = $windowEnd.AddDays(-$maxWindowDays)
            if ($windowStart -lt $startDate) { $windowStart = $startDate }

            $currentEnd = $windowEnd
            $startingRecipient = $null
            do {
                Write-Verbose "Retrieving message trace page $pageNum (Window $windowStart..$windowEnd, EndDate=$currentEnd)..."
                $traceParams = @{
                    SenderAddress = $Upn
                    StartDate     = $windowStart
                    EndDate       = $currentEnd
                    ResultSize    = $pageSize
                    ErrorAction   = 'Stop'
                }
                if ($startingRecipient) { $traceParams['StartingRecipientAddress'] = $startingRecipient }

                $batch = @(Get-MessageTraceV2 @traceParams | Where-Object { $null -ne $_ })

                if ($batch.Count -gt 0) {
                    foreach ($rec in $batch) {
                        if ($null -eq $rec) { continue }
                        $dedupKey = "$($rec.MessageTraceId)|$($rec.RecipientAddress)|$($rec.Received)"
                        if ($seenKeys.Add($dedupKey)) { $allMessages.Add($rec) }
                    }
                    $lastRecord = $batch[-1]
                    $currentEnd = $lastRecord.Received
                    $startingRecipient = $lastRecord.RecipientAddress
                    $pageNum++
                }
            } while ($batch.Count -eq $pageSize)

            # Move to the previous window; overlap at the boundary is removed by the dedup set.
            $windowEnd = $windowStart
        }
        
        Write-Information -MessageData "[INFO] Retrieved $($allMessages.Count) message trace records" -InformationAction Continue
        
        # Classify recipients as external/internal (in place, single pass).
        $acceptedDomainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($d in $acceptedDomains) { if ($d) { [void]$acceptedDomainSet.Add([string]$d) } }
        $messagesWithClassification = $allMessages
        foreach ($m in $messagesWithClassification) {
            $recipientDomain = ($m.RecipientAddress -split '@')[1]
            $isExternal = -not ($recipientDomain -and $acceptedDomainSet.Contains($recipientDomain))
            $m | Add-Member -NotePropertyName IsExternal -NotePropertyValue $isExternal -Force
        }
        
        # Retrieve per-recipient delivery detail events (Date / Event / Detail) via Get-MessageTraceDetailV2.
        # Fetch detail for every row (one call per recipient) so the report can show the delivery
        # timeline for all statuses, including Delivered. The total is still capped by MaxDetailLookups.
        $effectiveMaxDetail = if ($SkipMessageTraceDetail) { 0 } else { $MaxDetailLookups }
        $detailCandidates = @($messagesWithClassification | Where-Object { $_.MessageTraceId })
        $detailTargets = [System.Collections.Generic.List[object]]::new()
        $detailTargetIds = [System.Collections.Generic.HashSet[string]]::new()
        if ($effectiveMaxDetail -gt 0) {
            foreach ($c in ($detailCandidates | Select-Object -First $effectiveMaxDetail)) {
                $key = "$($c.MessageTraceId)|$($c.RecipientAddress)"
                if ($detailTargetIds.Add($key)) {
                    $detailTargets.Add([PSCustomObject]@{ Key = $key; MessageTraceId = $c.MessageTraceId; RecipientAddress = $c.RecipientAddress })
                }
            }
        }
        Write-Verbose "Delivery-detail lookups: $($detailTargets.Count) of $($detailCandidates.Count) recipient rows (cap $effectiveMaxDetail)."
        
        # Fetch the delivery-detail events into a key -> events dictionary. When -ParallelDetailLookups
        # is set AND there are enough targets to amortize the per-runspace EXO sign-in cost, fan the
        # calls across a runspace pool; otherwise (or on any pool failure) use the serial path. Both
        # paths apply 429/Retry-After back-off per call.
        $detailEventsByKey = @{}
        if ($detailTargets.Count -gt 0) {
            $parallelGate = $DetailThrottleLimit * 4
            $useParallel = $ParallelDetailLookups.IsPresent -and ($detailTargets.Count -ge $parallelGate)
            if ($useParallel) {
                try {
                    Write-Verbose "Using parallel detail lookups ($($detailTargets.Count) targets, $DetailThrottleLimit runspaces)."
                    $detailEventsByKey = Get-RrlDetailEventsBatch -Targets $detailTargets -AdminUpn $AdminUpn -ThrottleLimit $DetailThrottleLimit
                    if ($null -eq $detailEventsByKey) { throw "pool returned null" }
                }
                catch {
                    Write-Warning "Parallel detail lookups failed ($_); falling back to serial."
                    $detailEventsByKey = $null
                }
            }
            if (-not $useParallel -or $null -eq $detailEventsByKey) {
                $detailEventsByKey = @{}
                $sDone = 0
                foreach ($t in $detailTargets) {
                    if (($sDone % 25) -eq 0) {
                        Write-ProgressHelper -Status "Retrieving delivery detail events ($sDone of $($detailTargets.Count))..." -PercentComplete 30
                    }
                    $detailEventsByKey[$t.Key] = Get-RrlDetailEvents -MessageTraceId $t.MessageTraceId -RecipientAddress $t.RecipientAddress
                    $sDone++
                }
            }
        }
        
        # Assign fetched detail events onto each message row.
        foreach ($m in $messagesWithClassification) {
            $key = "$($m.MessageTraceId)|$($m.RecipientAddress)"
            $events = @()
            if ($detailEventsByKey.ContainsKey($key)) { $events = @($detailEventsByKey[$key]) }
            $m | Add-Member -NotePropertyName TraceDetails -NotePropertyValue $events -Force
        }
        
        # ----- Single-pass aggregation (daily, hourly, domains, status, uniques) -----
        $hourCutoff = $endDate.AddHours(-48)
        $allMsgIds = [System.Collections.Generic.HashSet[string]]::new()
        $uniqueExternalSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $internalCount = 0
        $daily = @{}
        $hourly = @{}
        $domainCounts = @{}
        $statusCounts = @{}
        $receivedTicks = [System.Collections.Generic.List[long]]::new()
        
        foreach ($m in $messagesWithClassification) {
            $received = $m.Received
            if ($received -is [datetime]) { $receivedTicks.Add($received.Ticks) }
            $msgId = [string]$m.MessageId
            if ($msgId) { [void]$allMsgIds.Add($msgId) }
            $isExt = [bool]$m.IsExternal
            $status = [string]$m.Status
            $domain = ($m.RecipientAddress -split '@')[1]
            
            if ($isExt) { if ($m.RecipientAddress) { [void]$uniqueExternalSet.Add([string]$m.RecipientAddress) } }
            else { $internalCount++ }
            
            if ($domain) { $domainCounts[$domain]++ }
            if ($status) { $statusCounts[$status]++ }
            
            if ($received -is [datetime]) {
                $dKey = $received.ToString('yyyy-MM-dd')
                $d = $daily[$dKey]
                if (-not $d) { $d = @{ Total = 0; Ext = 0; Int = 0; Delivered = 0; Failed = 0; Spam = 0; Ids = [System.Collections.Generic.HashSet[string]]::new() }; $daily[$dKey] = $d }
                $d.Total++
                if ($isExt) { $d.Ext++ } else { $d.Int++ }
                if ($msgId) { [void]$d.Ids.Add($msgId) }
                switch ($status) { 'Delivered' { $d.Delivered++ } 'Failed' { $d.Failed++ } 'FilteredAsSpam' { $d.Spam++ } }
                
                if ($received -ge $hourCutoff) {
                    $hKey = $received.ToString('yyyy-MM-dd HH:00')
                    $h = $hourly[$hKey]
                    if (-not $h) { $h = @{ Total = 0; Ext = 0; Int = 0; Ids = [System.Collections.Generic.HashSet[string]]::new() }; $hourly[$hKey] = $h }
                    $h.Total++
                    if ($isExt) { $h.Ext++ } else { $h.Int++ }
                    if ($msgId) { [void]$h.Ids.Add($msgId) }
                }
            }
        }
        
        $totalMessages = $allMsgIds.Count
        $totalRecipients = $messagesWithClassification.Count
        $uniqueExternalRecipients = @($uniqueExternalSet)
        
        $dailyStats = @($daily.GetEnumerator() | Sort-Object Key | ForEach-Object {
            $v = $_.Value
            [PSCustomObject]@{ Date = $_.Key; TotalRecipients = $v.Total; ExternalRecipients = $v.Ext; InternalRecipients = $v.Int; Messages = $v.Ids.Count; Delivered = $v.Delivered; Failed = $v.Failed; FilteredAsSpam = $v.Spam }
        })
        
        $hourlyStats = @($hourly.GetEnumerator() | Sort-Object Key | ForEach-Object {
            $v = $_.Value
            [PSCustomObject]@{ Hour = $_.Key; TotalRecipients = $v.Total; ExternalRecipients = $v.Ext; InternalRecipients = $v.Int; Messages = $v.Ids.Count }
        })
        
        # Peak rolling 60-minute window via two-pointer over Received-sorted timestamps (O(n log n)).
        $peakRollingWindow = 0
        if ($receivedTicks.Count -gt 0) {
            $sortedTicks = $receivedTicks.ToArray()
            [Array]::Sort($sortedTicks)
            $windowTicks = [timespan]::FromMinutes($script:RrlThresholds.BurstWindowMinutes).Ticks
            $left = 0
            for ($right = 0; $right -lt $sortedTicks.Length; $right++) {
                while (($sortedTicks[$right] - $sortedTicks[$left]) -ge $windowTicks) { $left++ }
                $count = $right - $left + 1
                if ($count -gt $peakRollingWindow) { $peakRollingWindow = $count }
            }
        }
        
        # Top recipient domains
        $topDomains = @($domainCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            [PSCustomObject]@{ Domain = $_.Key; Count = $_.Value }
        })
        
        # Status breakdown
        $statusBreakdown = @($statusCounts.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{ Status = $_.Key; Count = $_.Value }
        })
        
        return [PSCustomObject]@{
            Success = $true
            Error = $null
            TotalMessages = $totalMessages
            TotalRecipients = $totalRecipients
            UniqueExternalRecipients = $uniqueExternalRecipients.Count
            ExternalRecipientsList = $uniqueExternalRecipients
            InternalRecipientsCount = $internalCount
            DailyStats = $dailyStats
            HourlyStats = $hourlyStats
            PeakRolling60Min = $peakRollingWindow
            TopRecipientDomains = $topDomains
            StatusBreakdown = $statusBreakdown
            RawMessages = $messagesWithClassification
            AcceptedDomains = $acceptedDomains
        }
    }
    catch {
        return New-RrlError "Error retrieving message trace: $_" ([ordered]@{ TotalMessages = 0; TotalRecipients = 0 })
    }
}
#endregion

#region Get-RrlRestrictedEntity
function Get-RrlRestrictedEntity {
    <#
    .SYNOPSIS
        Checks if the user is in the restricted entities list (blocked sender).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipDefender
    )
    
    try {
        Write-ProgressHelper -Status "Checking restricted entities..." -PercentComplete 50
        
        # Get-BlockedSenderAddress is an Exchange Online cmdlet, so it runs regardless of -SkipDefender.
        if (-not (Get-Command Get-BlockedSenderAddress -ErrorAction SilentlyContinue)) {
            return New-RrlError "Get-BlockedSenderAddress cmdlet is unavailable (not connected to Exchange Online or insufficient permissions)." ([ordered]@{ IsBlocked = $false })
        }
        
        $normalizedUpn = ([string]$Upn).Trim()

        # CRITICAL: never pass -ErrorAction to Get-BlockedSenderAddress - binding it (any value)
        # triggers a spurious "server side error" and returns no data (a false "not restricted").
        # Capture errors via -ErrorVariable and suppress the noisy stream with 2>$null instead.
        $blockedSender  = $null
        $primaryErr     = $null
        $enumErr        = $null
        $enumRan        = $false

        # Primary: server-side filter (matches the confirmed working interactive command).
        $primaryResult = @(Get-BlockedSenderAddress -SenderAddress $normalizedUpn -ErrorVariable primaryErr 2>$null)
        $blockedSender = $primaryResult |
            Where-Object { $_.SenderAddress -and ([string]$_.SenderAddress).Trim() -ieq $normalizedUpn } |
            Select-Object -First 1
        if (-not $blockedSender -and $primaryResult.Count -gt 0) {
            # Filter returned rows but none matched exactly (unexpected) - take the first as a fallback.
            $blockedSender = $primaryResult | Select-Object -First 1
        }
        if (@($primaryErr).Count -gt 0) {
            Write-Verbose "Get-BlockedSenderAddress -SenderAddress reported: $(@($primaryErr)[0])"
        }

        # Fallback: enumerate all blocked senders and match case-insensitively. A successful
        # enumeration is authoritative for the "not blocked" determination.
        $primarySucceeded = (@($primaryErr).Count -eq 0)
        if (-not $blockedSender -and -not $primarySucceeded) {
            $enumRan = $true
            $allBlocked = @(Get-BlockedSenderAddress -ErrorVariable enumErr 2>$null)
            $blockedSender = $allBlocked |
                Where-Object { $_.SenderAddress -and ([string]$_.SenderAddress).Trim() -ieq $normalizedUpn } |
                Select-Object -First 1
            if (@($enumErr).Count -gt 0) {
                Write-Verbose "Get-BlockedSenderAddress (full list) reported: $(@($enumErr)[0])"
            }
        }

        $enumSucceeded = ($enumRan -and (@($enumErr).Count -eq 0))

        if ($blockedSender) {
            # Real Get-BlockedSenderAddress output exposes: SenderAddress, Reason,
            # CreatedDatetime, ChangedDatetime, TemporaryBlock. Older/remote builds may expose
            # LastBlockedDateTime instead. Resolve the block timestamp from whichever exists.
            $blockedWhen = $null
            foreach ($propName in @('CreatedDatetime', 'CreatedDateTime', 'LastBlockedDateTime', 'ChangedDatetime', 'ChangedDateTime')) {
                $prop = $blockedSender.PSObject.Properties[$propName]
                if ($prop -and $prop.Value) { $blockedWhen = $prop.Value; break }
            }
            $tempBlockProp = $blockedSender.PSObject.Properties['TemporaryBlock']
            return [PSCustomObject]@{
                Success              = $true
                Error                = $null
                IsBlocked            = $true
                BlockedSenderAddress = $blockedSender.SenderAddress
                LastBlockedDateTime  = $blockedWhen
                Reason               = $blockedSender.Reason
                Identity             = $blockedSender.SenderAddress
                TemporaryBlock       = if ($tempBlockProp) { $tempBlockProp.Value } else { $null }
            }
        }
        elseif ($primarySucceeded -or $enumSucceeded) {
            # A lookup completed without error and the user was not present -> genuinely not restricted.
            return [PSCustomObject]@{
                Success   = $true
                Error     = $null
                IsBlocked = $false
            }
        }
        elseif ((@($primaryErr).Count -gt 0) -or (@($enumErr).Count -gt 0)) {
            $errText = if (@($enumErr).Count -gt 0) { "$(@($enumErr)[0])" } else { "$(@($primaryErr)[0])" }
            if ([string]::IsNullOrWhiteSpace($errText)) {
                $errText = "The Get-BlockedSenderAddress lookup did not complete (Exchange Online returned a transient error)."
            }
            return New-RrlError "Error checking restricted entities: $errText" ([ordered]@{ IsBlocked = $false })
        }
        else {
            return [PSCustomObject]@{
                Success   = $true
                Error     = $null
                IsBlocked = $false
            }
        }
    }
    catch {
        return New-RrlError "Error checking restricted entities: $_" ([ordered]@{ IsBlocked = $false })
    }
}
#endregion

#region Get-RrlSendAsLogs
function Get-RrlSendAsLogs {
    <#
    .SYNOPSIS
        Retrieves SendAs / SendOnBehalf events for the affected mailbox from the unified
        audit log (Search-UnifiedAuditLog) and normalizes the AuditData JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,

        [Parameter(Mandatory = $true)]
        [int]$LookbackDays,

        [Parameter(Mandatory = $false)]
        [switch]$SkipDefender
    )

    try {
        if ($SkipDefender) {
            return [PSCustomObject]@{ Success = $true; Error = $null; Found = $false; Count = 0; Entries = @(); Skipped = $true }
        }

        Write-ProgressHelper -Status "Retrieving SendAs / SendOnBehalf unified audit logs..." -PercentComplete 55

        if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
            return New-RrlError "Search-UnifiedAuditLog cmdlet is unavailable (not connected to Security & Compliance)." ([ordered]@{ Found = $false; Count = 0; Entries = @(); Skipped = $false })
        }

        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$LookbackDays)
        $raw = @(Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations 'SendAs', 'SendOnBehalf' -UserIds $Upn -ResultSize 5000 -ErrorAction SilentlyContinue)

        $entries = foreach ($r in $raw) {
            $data = $null
            try { $data = $r.AuditData | ConvertFrom-Json } catch { $data = $null }
            if (-not $data) { continue }
            [PSCustomObject]@{
                CreationTime           = [string]$data.CreationTime
                Operation              = [string]$data.Operation
                UserId                 = [string]$data.UserId
                SendAsUserSmtp         = [string]$data.SendAsUserSmtp
                SendOnBehalfOfUserSmtp = [string]$data.SendOnBehalfOfUserSmtp
                MailboxOwnerUPN        = [string]$data.MailboxOwnerUPN
                ClientIP               = [string]$data.ClientIP
                Subject                = if ($data.Item -and $data.Item.Subject) { [string]$data.Item.Subject } else { '' }
                InternetMessageId      = if ($data.Item -and $data.Item.InternetMessageId) { [string]$data.Item.InternetMessageId } else { '' }
                ResultStatus           = [string]$data.ResultStatus
                Workload               = [string]$data.Workload
            }
        }
        $entries = @($entries)

        return [PSCustomObject]@{
            Success = $true
            Error   = $null
            Found   = ($entries.Count -gt 0)
            Count   = $entries.Count
            Entries = $entries
            Skipped = $false
        }
    }
    catch {
        return New-RrlError "Error retrieving SendAs unified audit logs: $_" ([ordered]@{ Found = $false; Count = 0; Entries = @(); Skipped = $false })
    }
}
#endregion

#region Get-RrlDefenderAlerts
function Get-RrlDefenderAlerts {
    <#
    .SYNOPSIS
        Retrieves Microsoft Defender alerts for the affected user from Microsoft Graph
        (security/alerts_v2) and filters them to the affected user only.
        Gracefully handles a missing Graph connection or SecurityAlert.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,
        
        [Parameter(Mandatory = $false)]
        [string]$DisplayName,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipDefender,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipHistoricalSearch
    )
    
    try {
        if ($SkipDefender -or $SkipHistoricalSearch) {
            return [PSCustomObject]@{
                Success = $true
                Error = $null
                AlertsFound = $false
                AlertCount = 0
                Alerts = @()
                Skipped = $true
            }
        }
        
        Write-ProgressHelper -Status "Retrieving Defender alerts..." -PercentComplete 60
        
        # Defender alerts come from Microsoft Graph (security/alerts_v2), which requires
        # a Graph connection with the SecurityAlert.Read.All scope.
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $graphContext) {
            return [PSCustomObject]@{
                Success = $true
                Error = 'Microsoft Graph is not connected; Defender alerts were not retrieved.'
                AlertsFound = $false
                AlertCount = 0
                Alerts = @()
                Skipped = $false
            }
        }
        if ($graphContext.Scopes -notcontains 'SecurityAlert.Read.All') {
            return [PSCustomObject]@{
                Success = $true
                Error = 'SecurityAlert.Read.All permission not granted; Defender alerts were not retrieved. Re-run and consent to all requested permissions.'
                AlertsFound = $false
                AlertCount = 0
                Alerts = @()
                Skipped = $false
            }
        }
        
        # Retrieve all alerts from the last 30 days, paging through @odata.nextLink.
        $startDate = (Get-Date).AddDays(-30).ToUniversalTime()
        $filterQuery = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        $nextLink = "https://graph.microsoft.com/beta/security/alerts_v2?`$filter=$filterQuery"
        
        $allAlerts = @()
        try {
            while ($nextLink) {
                $response = Invoke-MgGraphRequest -Uri $nextLink -Method GET -OutputType PSObject -ErrorAction Stop
                if ($response.value) { $allAlerts += $response.value }
                $nextLink = $response.'@odata.nextLink'
            }
        }
        catch {
            return New-RrlError "Error retrieving Defender alerts from Microsoft Graph: $_" ([ordered]@{ AlertsFound = $false; AlertCount = 0; Alerts = @(); Skipped = $false })
        }
        
        $normalizedUpn = $Upn.Trim().ToLowerInvariant()
        $normalizedDisplay = if ($DisplayName) { $DisplayName.Trim().ToLowerInvariant() } else { $null }
        
        $alerts = @()
        foreach ($alert in $allAlerts) {
            # Extract evidence (user, device, IP) from the alert.
            $alertUserDisplayName = $null
            $userPrimaryAddress = $null
            $userAccountEnabled = $null
            $deviceName = $null
            $alertIPAddress = $null
            if ($alert.evidence) {
                foreach ($ev in $alert.evidence) {
                    $et = $ev.'@odata.type'
                    if ($et -eq '#microsoft.graph.security.userEvidence') {
                        if (-not $alertUserDisplayName) { $alertUserDisplayName = $ev.userAccount.displayName }
                        if (-not $userPrimaryAddress) {
                            $userPrimaryAddress = if ($ev.userAccount.userPrincipalName) { $ev.userAccount.userPrincipalName }
                                elseif ($ev.userAccount.accountName -and $ev.userAccount.domainName) { "$($ev.userAccount.accountName)@$($ev.userAccount.domainName)" }
                                elseif ($ev.userAccount.accountName) { $ev.userAccount.accountName }
                                else { $null }
                        }
                        if ($null -eq $userAccountEnabled) { $userAccountEnabled = $ev.userAccount.accountEnabled }
                    }
                    elseif ($et -eq '#microsoft.graph.security.deviceEvidence' -and -not $deviceName) {
                        $deviceName = if ($ev.deviceDnsName) { $ev.deviceDnsName } elseif ($ev.deviceName) { $ev.deviceName } elseif ($ev.azureAdDeviceId) { $ev.azureAdDeviceId } else { $null }
                    }
                    elseif ($et -eq '#microsoft.graph.security.ipEvidence' -and -not $alertIPAddress) {
                        $alertIPAddress = $ev.ipAddress
                    }
                }
            }
            
            # Keep only alerts that concern the affected user (match on UPN or display name).
            $matchesUser = $false
            if ($userPrimaryAddress -and $userPrimaryAddress.Trim().ToLowerInvariant() -eq $normalizedUpn) { $matchesUser = $true }
            elseif ($normalizedDisplay -and $alertUserDisplayName -and $alertUserDisplayName.Trim().ToLowerInvariant() -eq $normalizedDisplay) { $matchesUser = $true }
            
            if ($matchesUser) {
                $mitre = if ($alert.mitreTechniques) { @($alert.mitreTechniques) -join ', ' } else { $null }
                $evidenceSummary = if ($alert.evidence) { (@($alert.evidence | ForEach-Object { $_.'@odata.type' -replace '#microsoft\.graph\.security\.', '' }) -join ', ') } else { $null }
                $comments = if ($alert.comments) { (@($alert.comments | ForEach-Object { "$($_.createdDateTime) - $($_.createdBy): $($_.comment)" }) -join ' | ') } else { $null }
                $recActions = if ($alert.recommendedActions) { [string]$alert.recommendedActions } else { $null }
                $alerts += [PSCustomObject]@{
                    CreationDate      = $alert.createdDateTime
                    AlertName         = $alert.title
                    Severity          = $alert.severity
                    Category          = $alert.category
                    Status            = $alert.status
                    AlertId           = $alert.id
                    Description       = $alert.description
                    UserPrincipalName = $userPrimaryAddress
                    UserDisplayName   = $alertUserDisplayName
                    UserAccountEnabled = $userAccountEnabled
                    DeviceName        = $deviceName
                    IPAddress         = $alertIPAddress
                    AlertWebUrl       = $alert.alertWebUrl
                    Classification    = $alert.classification
                    Determination     = $alert.determination
                    DetectionSource   = $alert.detectionSource
                    ServiceSource     = $alert.serviceSource
                    ProviderAlertId   = $alert.providerAlertId
                    ThreatFamilyName  = $alert.threatFamilyName
                    ThreatDisplayName = $alert.threatDisplayName
                    ActorDisplayName  = $alert.actorDisplayName
                    AssignedTo        = $alert.assignedTo
                    IncidentId        = $alert.incidentId
                    IncidentWebUrl    = $alert.incidentWebUrl
                    FirstActivity     = $alert.firstActivityDateTime
                    LastActivity      = $alert.lastActivityDateTime
                    LastUpdate        = $alert.lastUpdateDateTime
                    ResolvedDateTime  = $alert.resolvedDateTime
                    MitreTechniques   = $mitre
                    EvidenceCount     = if ($alert.evidence) { @($alert.evidence).Count } else { 0 }
                    EvidenceSummary   = $evidenceSummary
                    RecommendedActions = $recActions
                    Comments          = $comments
                    TenantId          = $alert.tenantId
                }
            }
        }
        
        return [PSCustomObject]@{
            Success = $true
            Error = $null
            AlertsFound = $alerts.Count -gt 0
            AlertCount = $alerts.Count
            Alerts = $alerts
            Skipped = $false
        }
    }
    catch {
        return New-RrlError "Error retrieving Defender alerts: $_" ([ordered]@{ AlertsFound = $false; AlertCount = 0; Alerts = @(); Skipped = $false })
    }
}
#endregion

#region Start-RrlGraphLane
function Start-RrlGraphLane {
    <#
    .SYNOPSIS
        Launches the Microsoft Graph "lane" (Defender-alert retrieval) concurrently so it
        overlaps the Exchange Online data collection running on the main runspace.
    .DESCRIPTION
        Graph auth is token-based and the SDK's session is a process-wide singleton, so a
        second in-process runspace (or ThreadJob) reuses the existing Connect-MgGraph session
        without re-authenticating. EXO cmdlets are NOT thread-safe across runspaces, so only
        the pure-Graph Defender work is offloaded here.
        Returns a lane handle, or $null if no concurrency mechanism is available (caller then
        runs the work inline).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Upn,
        [Parameter(Mandatory = $false)][string]$DisplayName,
        [Parameter(Mandatory = $false)][switch]$SkipDefender,
        [Parameter(Mandatory = $false)][switch]$SkipHistoricalSearch
    )

    # Capture the current function bodies so the worker runspace can run them without the
    # whole script being loaded. Write-ProgressHelper is replaced with a no-op in the lane.
    $progressNoop = 'function Write-ProgressHelper { param([string]$Status, [int]$PercentComplete) }'
    $defenderDef = "function Get-RrlDefenderAlerts {`n" + (Get-Command Get-RrlDefenderAlerts).Definition + "`n}"

    $laneScript = {
        param($upn, $displayName, $skipDef, $skipHist, $progressNoop, $defenderDef)
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        . ([ScriptBlock]::Create($progressNoop))
        . ([ScriptBlock]::Create($defenderDef))
        Get-RrlDefenderAlerts -Upn $upn -DisplayName $displayName -SkipDefender:$skipDef -SkipHistoricalSearch:$skipHist
    }

    try {
        if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
            $job = Start-ThreadJob -ScriptBlock $laneScript -ArgumentList $Upn, $DisplayName, $SkipDefender.IsPresent, $SkipHistoricalSearch.IsPresent, $progressNoop, $defenderDef
            return [PSCustomObject]@{ Kind = 'ThreadJob'; Job = $job }
        }

        $ps = [PowerShell]::Create()
        [void]$ps.AddScript($laneScript.ToString())
        [void]$ps.AddArgument($Upn)
        [void]$ps.AddArgument($DisplayName)
        [void]$ps.AddArgument($SkipDefender.IsPresent)
        [void]$ps.AddArgument($SkipHistoricalSearch.IsPresent)
        [void]$ps.AddArgument($progressNoop)
        [void]$ps.AddArgument($defenderDef)
        $async = $ps.BeginInvoke()
        return [PSCustomObject]@{ Kind = 'Runspace'; PS = $ps; Async = $async }
    }
    catch {
        Write-Verbose "Start-RrlGraphLane failed to launch concurrency ($_); caller will run inline."
        return $null
    }
}
#endregion

#region Receive-RrlGraphLane
function Receive-RrlGraphLane {
    <#
    .SYNOPSIS
        Blocks until the Graph lane finishes (or times out) and returns its result object.
        Returns $null on timeout/error so the caller can fall back to an inline computation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lane,
        [Parameter(Mandatory = $false)][int]$TimeoutSeconds = 180
    )
    try {
        if ($Lane.Kind -eq 'ThreadJob') {
            $null = Wait-Job -Job $Lane.Job -Timeout $TimeoutSeconds
            $res = Receive-Job -Job $Lane.Job -ErrorAction SilentlyContinue
            Remove-Job -Job $Lane.Job -Force -ErrorAction SilentlyContinue
            return (@($res) | Where-Object { $_ } | Select-Object -Last 1)
        }
        else {
            $done = $Lane.Async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)
            $res = $null
            if ($done) { $res = $Lane.PS.EndInvoke($Lane.Async) }
            try { $Lane.PS.Dispose() } catch { }
            if (-not $done) { return $null }
            return (@($res) | Where-Object { $_ } | Select-Object -Last 1)
        }
    }
    catch {
        Write-Verbose "Receive-RrlGraphLane error: $_"
        return $null
    }
}
#endregion

#region Measure-RrlStep
function Measure-RrlStep {
    <#
    .SYNOPSIS
        Runs a collection step, records its wall-clock duration in $script:RrlTimings,
        and emits a verbose timing line. Returns the step's result unchanged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    if (-not $script:RrlTimings) { $script:RrlTimings = [ordered]@{} }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Script
    }
    finally {
        $sw.Stop()
        $script:RrlTimings[$Name] = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        Write-Verbose ("[TIMING] {0}: {1:N2}s" -f $Name, $sw.Elapsed.TotalSeconds)
    }
    return $result
}
#endregion

#region Get-RrlAccountHealth
function Get-RrlAccountHealth {
    <#
    .SYNOPSIS
        Checks account health signals: forwarding and inbox rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,
        
        [Parameter(Mandatory = $false)]
        $Mailbox
    )
    
    try {
        Write-ProgressHelper -Status "Checking account health and security signals..." -PercentComplete 70
        
        # Reuse the mailbox retrieved during recipient validation when available; otherwise fetch it.
        $mailbox = $Mailbox
        if (-not $mailbox) {
            $mailbox = Get-EXOMailbox -Identity $Upn -Properties ForwardingSmtpAddress, DeliverToMailboxAndForward -ErrorAction SilentlyContinue
        }
        
        $hasExternalForward = $false
        $forwardingAddress = $null
        if ($mailbox -and $mailbox.ForwardingSmtpAddress) {
            $hasExternalForward = $true
            $forwardingAddress = $mailbox.ForwardingSmtpAddress
        }
        
        # Get inbox rules
        $inboxRules = Get-InboxRule -Mailbox $Upn -ErrorAction SilentlyContinue
        
        $securitySignalsRules = @()
        if ($inboxRules) {
            $securitySignalsRules = @($inboxRules | Where-Object {
                $_.ForwardTo -or $_.RedirectTo -or $_.DeleteMessage -eq $true
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    ForwardTo = $_.ForwardTo
                    RedirectTo = $_.RedirectTo
                    DeleteMessage = $_.DeleteMessage
                    Description = $_.Description
                    Priority = $_.Priority
                    MailboxOwnerId = $_.MailboxOwnerId
                }
            })
        }
        
        return [PSCustomObject]@{
            Success = $true
            Error = $null
            HasExternalForward = $hasExternalForward
            ForwardingAddress = $forwardingAddress
            DeliverToMailboxAndForward = if ($mailbox) { $mailbox.DeliverToMailboxAndForward } else { $false }
            SecuritySignalsRulesCount = $securitySignalsRules.Count
            SecuritySignalsRules = $securitySignalsRules
        }
    }
    catch {
        return New-RrlError "Error checking account health: $_" ([ordered]@{ HasExternalForward = $false; SecuritySignalsRulesCount = 0 })
    }
}
#endregion

#region Get-RrlSecuritySignals
function Get-RrlSecuritySignals {
    <#
    .SYNOPSIS
        Collects supplemental mail-flow and threat signals used by the
        expanded Security Signals.
    .NOTES
        READ-ONLY. Every signal is best-effort: missing modules, permissions, or
        cmdlets are caught and the corresponding indicator degrades gracefully.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Upn,

        [Parameter(Mandatory = $false)]
        [switch]$SkipDefender
    )

    Write-ProgressHelper -Status "Collecting identity and threat signals..." -PercentComplete 75

    # --- B2: Delegation / SendAs permissions ---
    $delegationFound = $false
    $delegationEntries = @()
    try {
        $fullAccess = @(Get-EXOMailboxPermission -Identity $Upn -ErrorAction SilentlyContinue |
            Where-Object { $_.AccessRights -contains 'FullAccess' -and $_.User -notlike 'NT AUTHORITY\SELF' -and $_.User -notlike 'S-1-*' })
        $sendAs = @(Get-EXORecipientPermission -Identity $Upn -ErrorAction SilentlyContinue |
            Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' -and $_.AccessRights -contains 'SendAs' })
        $delegates = @()
        $delegates += @($fullAccess | ForEach-Object { "$($_.User) (FullAccess)" })
        $delegates += @($sendAs | ForEach-Object { "$($_.Trustee) (SendAs)" })
        $delegationEntries += @($fullAccess | ForEach-Object {
            [PSCustomObject]@{
                PermissionType    = 'FullAccess'
                User              = [string]$_.User
                AccessRights      = (@($_.AccessRights) | ForEach-Object { [string]$_ }) -join ', '
                AccessControlType = ''
                Deny              = [string]$_.Deny
                InheritanceType   = [string]$_.InheritanceType
            }
        })
        $delegationEntries += @($sendAs | ForEach-Object {
            [PSCustomObject]@{
                PermissionType    = 'SendAs'
                User              = [string]$_.Trustee
                AccessRights      = (@($_.AccessRights) | ForEach-Object { [string]$_ }) -join ', '
                AccessControlType = [string]$_.AccessControlType
                Deny              = ''
                InheritanceType   = ''
            }
        })
        if ($delegates.Count -gt 0) {
            $delegationFound = $true
        }
    }
    catch { Write-Verbose "Delegation lookup failed: $_" }

    # --- E2: Quarantined messages ---
    $quarantineCount = 0
    $quarantineTypes = @()
    $quarantineMessages = @()
    $quarantineLookupError = $null
    if (-not $SkipDefender) {
        try {
            if (Get-Command Get-QuarantineMessage -ErrorAction SilentlyContinue) {
                $qm = @(Get-QuarantineMessage -SenderAddress $Upn -ErrorAction Stop)
                $quarantineCount = $qm.Count
                $quarantineMessages = @($qm | ForEach-Object {
                    [PSCustomObject]@{
                        MessageId       = [string]$_.MessageId
                        SenderAddress   = [string]$_.SenderAddress
                        RecipientAddress = (@($_.RecipientAddress) | ForEach-Object { [string]$_ }) -join ', '
                        Subject         = [string]$_.Subject
                        Type            = [string]$_.Type
                        EntityType      = [string]$_.EntityType
                        PolicyType      = [string]$_.PolicyType
                        PolicyName      = [string]$_.PolicyName
                        QuarantineTypes = (@($_.QuarantineTypes) | ForEach-Object { [string]$_ }) -join ', '
                        ReleaseStatus   = [string]$_.ReleaseStatus
                        ReceivedTime    = if ($_.ReceivedTime) { ([datetime]$_.ReceivedTime).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                        SystemReleased  = [string]$_.SystemReleased
                        Expires         = if ($_.Expires) { ([datetime]$_.Expires).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                        Reported        = [string]$_.Reported
                    }
                })
                $quarantineTypes = @($qm | ForEach-Object { @($_.QuarantineTypes) + @($_.Type) } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                    Select-Object -Unique)
            }
            else { $quarantineLookupError = 'Get-QuarantineMessage is not available in the current session' }
        }
        catch {
            $quarantineLookupError = [string]$_
            Write-Verbose "Quarantine lookup failed: $_"
        }
    }

    # --- Unified audit (mailbox audit logging) status ---
    $auditEnabled = $null
    $auditProperties = @()
    try {
        if (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) {
            $mbxAudit = Get-Mailbox -Identity $Upn -ErrorAction Stop | Select-Object *audit*
            if ($mbxAudit) {
                if ($mbxAudit.PSObject.Properties['AuditEnabled']) { $auditEnabled = [bool]$mbxAudit.AuditEnabled }
                $auditProperties = @($mbxAudit.PSObject.Properties | ForEach-Object {
                    [PSCustomObject]@{
                        Name  = [string]$_.Name
                        Value = if ($null -ne $_.Value -and $_.Value -is [System.Collections.IEnumerable] -and $_.Value -isnot [string]) { (@($_.Value) | ForEach-Object { [string]$_ }) -join ', ' } else { [string]$_.Value }
                    }
                })
            }
        }
    }
    catch { Write-Verbose "Unified audit status lookup failed: $_" }

    return [PSCustomObject]@{
        Success              = $true
        DelegationFound      = $delegationFound
        DelegationEntries    = $delegationEntries
        QuarantineCount      = $quarantineCount
        QuarantineTypes      = $quarantineTypes
        QuarantineMessages   = $quarantineMessages
        QuarantineLookupError = $quarantineLookupError
        AuditEnabled         = $auditEnabled
        AuditProperties      = $auditProperties
    }
}
#endregion

#endregion

#region Verdict Engine

#region Invoke-RrlVerdictAnalysis
function Invoke-RrlVerdictAnalysis {
    <#
    .SYNOPSIS
        Applies the decision tree and indicator counts to classify the RRL block.
        Returns a structured verdict with classification, block type, and evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$RrlData,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Thresholds
    )
    
    try {
        Write-ProgressHelper -Status "Analyzing evidence and determining verdict..." -PercentComplete 80
        
        # Extract data
        $policy = $RrlData.Policy
        $trace = $RrlData.MessageTrace
        $restricted = $RrlData.RestrictedEntity
        $alerts = $RrlData.DefenderAlerts
        $health = $RrlData.AccountHealth
        
        # Initialize verdict components
        $classification = 'NO_BLOCK_FOUND'
        $blockType = $null
        $evidence = @()
        
        # Effective daily limit: MIN(policy, RRL default)
        $effectiveDailyLimit = [Math]::Min($policy.RecipientLimitPerDay, $Thresholds.DefaultRrlDailyLimit)
        
        # Max daily recipients from trace
        $maxDailyRecipients = 0
        if ($trace.Success -and $trace.DailyStats) {
            $maxDailyRecipients = ($trace.DailyStats | Measure-Object -Property TotalRecipients -Maximum).Maximum
        }
        
        # security signals evaluation
        # Each indicator is evaluated explicitly so its condition and met/not-met
        # status can be surfaced in the report for the end user.
        $securitySignals = @()

        # Indicator 1: External forwarding
        $extFwdMet = [bool]($health.Success -and $health.HasExternalForward)
        $extFwdDetail = if ($extFwdMet) { "Forwarding to: $($health.ForwardingAddress)" } else { 'No external forwarding configured' }
        $securitySignals += New-RrlIndicator -Name 'External forwarding' -Condition 'Mailbox has an external forwarding SMTP address configured' -Met $extFwdMet -Detail $extFwdDetail -DetailType 'externalForwarding'

        # Indicator 2: Inbox rules
        $rulesMet = [bool]($health.Success -and $health.SecuritySignalsRulesCount -gt 0)
        $rulesDetail = if ($rulesMet) { "$($health.SecuritySignalsRulesCount) suspicious rule(s) detected" } else { 'No suspicious inbox rules' }
        $securitySignals += New-RrlIndicator -Name 'Inbox rules' -Condition 'Inbox rules that forward, redirect, or delete messages exist' -Met $rulesMet -Detail $rulesDetail -DetailType 'inboxRules'

        $sec = $null
        if ($RrlData.ContainsKey('SecuritySignals')) { $sec = $RrlData.SecuritySignals }
        $rawMsgs = @()
        if ($trace.Success -and $trace.RawMessages) { $rawMsgs = @($trace.RawMessages) }
        $freeWebmail = @('gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com', 'proton.me', 'mail.com', 'aol.com', 'gmx.com', 'yandex.com', 'icloud.com', 'zoho.com', 'live.com', 'msn.com')

        # B1: Auto-forwarding to free webmail
        $fwTargets = @()
        if ($health.Success) {
            if ($health.ForwardingAddress) { $fwTargets += [PSCustomObject]@{ Target = [string]$health.ForwardingAddress; Source = 'Mailbox forwarding (ForwardingSmtpAddress)' } }
            if ($health.SecuritySignalsRules) {
                foreach ($rl in $health.SecuritySignalsRules) {
                    if ($rl.ForwardTo) { $fwTargets += @($rl.ForwardTo | ForEach-Object { [PSCustomObject]@{ Target = [string]$_; Source = "Inbox rule '$($rl.Name)' (ForwardTo)" } }) }
                    if ($rl.RedirectTo) { $fwTargets += @($rl.RedirectTo | ForEach-Object { [PSCustomObject]@{ Target = [string]$_; Source = "Inbox rule '$($rl.Name)' (RedirectTo)" } }) }
                }
            }
        }
        $freeFwd = @()
        $freeFwdEntries = @()
        foreach ($ft in $fwTargets) {
            foreach ($dom in $freeWebmail) {
                if ($ft.Target -match [regex]::Escape($dom)) {
                    $freeFwd += $ft.Target
                    $freeFwdEntries += [PSCustomObject]@{ Target = $ft.Target; Source = $ft.Source; MatchedDomain = $dom }
                    break
                }
            }
        }
        $freeFwdMet = [bool]($freeFwd.Count -gt 0)
        $freeFwdDetail = if ($freeFwdMet) { "Target(s): $(($freeFwd | Select-Object -Unique) -join '; ')" } else { 'No forwarding to free webmail detected' }
        $securitySignals += New-RrlIndicator -Name 'Auto-forward to free webmail' -Condition 'Forwarding/redirect target is a free webmail domain (gmail, outlook, yahoo, etc.)' -Met $freeFwdMet -Detail $freeFwdDetail -DetailType 'freeWebmail' -Entries $freeFwdEntries
        # B2: Delegation or SendAs granted
        $delegMet = [bool]($sec -and $sec.DelegationFound)
        $delegDetailText = 'Signal not collected'
        if ($sec) {
            $delegEntries = @($sec.DelegationEntries)
            $fullAccessCount = @($delegEntries | Where-Object { $_.PermissionType -eq 'FullAccess' }).Count
            $sendAsCount = @($delegEntries | Where-Object { $_.PermissionType -eq 'SendAs' }).Count
            $delegDetailText = "FullAccess: $fullAccessCount; SendAs: $sendAsCount"
        }
        $securitySignals += New-RrlIndicator -Name 'Delegation or SendAs permissions' -Condition 'Another account holds FullAccess or SendAs on this mailbox' -Met $delegMet -Detail $delegDetailText -DetailType 'delegation'
        # C2: High NDR / bounce rate
        # C3: Midnight / off-hours sending spike
        # D1: High similarity of message subjects
        $subjMet = $false; $subjTop = 0; $subjTopPercentage = 0
        $subjectEntries = @()
        if ($rawMsgs.Count -gt 10) {
            $subjGroups = @($rawMsgs | Group-Object Subject | Sort-Object Count -Descending)
            if ($subjGroups.Count -gt 0) {
                $subjTop = $subjGroups[0].Count
            $subjTopPercentage = [math]::Round(($subjTop / $rawMsgs.Count) * 100, 1)
            $subjMet = [bool](($subjTop / $rawMsgs.Count) -ge $Thresholds.SubjectSimilarityThreshold)
                $subjectEntries = @($subjGroups | Select-Object -First 5 | ForEach-Object {
                    $latestReceived = @($_.Group | Where-Object { $_.Received } | ForEach-Object { [datetime]$_.Received } | Sort-Object -Descending | Select-Object -First 1)
                    [PSCustomObject]@{
                        Subject          = if ([string]::IsNullOrEmpty($_.Name)) { '(no subject)' } else { [string]$_.Name }
                        MessageCount     = [int]$_.Count
                        Percentage       = [math]::Round(($_.Count / $rawMsgs.Count) * 100, 1)
                        SentDateTime     = if ($latestReceived.Count -gt 0) { $latestReceived[0].ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    }
                })
            }
        }
        $subjDetail = if ($rawMsgs.Count -gt 10) { "Top subject covers $subjTop of $($rawMsgs.Count) recipient rows ($subjTopPercentage%)" } else { 'Insufficient message volume to assess' }
        $securitySignals += New-RrlIndicator -Name 'High similarity of message subjects' -Condition 'At least 50% of message-trace recipient rows share one exact subject line (evaluated only when more than 10 rows exist)' -Met $subjMet -Detail $subjDetail -DetailType 'subjectSimilarity' -Entries $subjectEntries
        # E1: Active Defender alerts
        $alertMet = $false; $alertDetail = 'No Defender alerts'
        if ($alerts.Success -and $alerts.AlertsFound) {
            $activeAlerts = @($alerts.Alerts | Where-Object {
                $normalizedStatus = ([string]$_.Status -replace '\s', '').ToLowerInvariant()
                $normalizedStatus -in @('new', 'inprogress')
            })
            $alertMet = [bool]($activeAlerts.Count -gt 0)
            $alertDetail = if ($alertMet) { "$($activeAlerts.Count) alert(s) require attention (New or In progress)" } else { "$($alerts.AlertCount) alert(s), none require attention" }
        }
        elseif ($alerts.Success -and $alerts.Skipped) { $alertDetail = 'Defender search skipped' }
        $securitySignals += New-RrlIndicator -Name 'Active Defender alerts' -Condition 'At least 1 Defender alert with status New or In progress in last 30 days' -Met $alertMet -Detail $alertDetail -DetailType 'defenderAlerts'
        # E2: Messages quarantined
        $quarMet = [bool]($sec -and $sec.QuarantineCount -ge 1)
        $quarantineTypeDetail = if ($sec -and @($sec.QuarantineTypes).Count -gt 0) {
            @($sec.QuarantineTypes) -join ', '
        }
        else { 'Not specified' }
        $quarDetail = if ($sec -and $sec.QuarantineLookupError) { "Quarantine lookup failed: $($sec.QuarantineLookupError)" } elseif ($sec) { "Outbound messages quarantined from this sender: $($sec.QuarantineCount); Quarantine types: $quarantineTypeDetail" } else { 'Signal not collected' }
        $quarMessages = if ($sec) { @($sec.QuarantineMessages) } else { @() }
        $securitySignals += New-RrlIndicator -Name 'Outbound messages quarantined' -Condition 'At least 1 outbound message sent by this sender was quarantined' -Met $quarMet -Detail $quarDetail -DetailType 'quarantineMessages' -Messages $quarMessages

        # Unified audit (mailbox audit logging) enabled
        $auditEnabledVal = if ($sec) { $sec.AuditEnabled } else { $null }
        $auditMet = ($null -ne $auditEnabledVal -and -not [bool]$auditEnabledVal)
        $auditDetail = if ($null -eq $auditEnabledVal) { 'Signal not collected' } elseif ([bool]$auditEnabledVal) { 'Unified Audit Log is enabled (AuditEnabled = True)' } else { 'Unified Audit Log is not enabled (AuditEnabled = False)' }
        $auditEntries = if ($sec -and $sec.AuditProperties) { @($sec.AuditProperties) } else { @() }
        $securitySignals += New-RrlIndicator -Name 'Unified Audit Enabled' -Condition 'Mailbox audit logging (AuditEnabled) is turned on' -Met $auditMet -Detail $auditDetail -DetailType 'auditEnabled' -Entries $auditEntries

        # Count indicators requiring attention (drives the security-insights donut).
        $attentionNeededCount = 0
        foreach ($ind in $securitySignals) {
            if ($ind.Met) { $attentionNeededCount++ }
        }
        $noAttentionCount = $securitySignals.Count - $attentionNeededCount
        
        # Decision tree: a restriction is always an expected block. Classify the specific
        # limit when the trace proves it (daily/hourly); otherwise report a generic
        # EXPECTED_BLOCK and name the cause from Microsoft's reported ExceedingLimitType.
        if ($restricted.Success -and $restricted.IsBlocked) {
            # Microsoft encodes the triggering limit in the semicolon-delimited Reason string.
            $exceedingLimitType = $null
            foreach ($pair in ([string]$restricted.Reason -split ';')) {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2 -and $kv[0].Trim() -eq 'ExceedingLimitType') { $exceedingLimitType = $kv[1].Trim() }
            }
            if ($maxDailyRecipients -ge $effectiveDailyLimit) {
                $classification = 'EXPECTED_BLOCK_DAILY'
                $blockType = 'Daily recipient limit exceeded'
                $evidence += "Daily limit breach: $maxDailyRecipients recipients sent (limit: $effectiveDailyLimit)"
            }
            elseif ($trace.Success -and $trace.HourlyStats) {
                # Check hourly limits
                $maxHourlyExternal = ($trace.HourlyStats | Measure-Object -Property ExternalRecipients -Maximum).Maximum
                $maxHourlyInternal = ($trace.HourlyStats | Measure-Object -Property InternalRecipients -Maximum).Maximum
                
                if ($maxHourlyExternal -ge $policy.RecipientLimitExternalPerHour -or $maxHourlyInternal -ge $policy.RecipientLimitInternalPerHour) {
                    $classification = 'EXPECTED_BLOCK_HOURLY'
                    $blockType = 'Hourly recipient limit exceeded'
                    $extLimit = $policy.RecipientLimitExternalPerHour
                    $intLimit = $policy.RecipientLimitInternalPerHour
                    $extStatus = if ($maxHourlyExternal -ge $extLimit) { 'EXCEEDED' } else { 'within limit' }
                    $intStatus = if ($maxHourlyInternal -ge $intLimit) { 'EXCEEDED' } else { 'within limit' }
                    $extPart = "External recipients/hour: found $maxHourlyExternal vs policy limit $extLimit ($extStatus)"
                    $intPart = "Internal recipients/hour: found $maxHourlyInternal vs policy limit $intLimit ($intStatus)"
                    $evidence += $extPart
                    $evidence += $intPart
                }
                else {
                    # Restricted, but no specific daily/hourly breach proven by the trace.
                    $classification = 'EXPECTED_BLOCK'
                    $blockType = if ($exceedingLimitType) { "Microsoft-reported restriction (ExceedingLimitType = $exceedingLimitType)" } else { 'Other outbound sending restriction (e.g. message-rate limit, outbound spam, or malware detection)' }
                }
            }
            else {
                # Restricted but no trace data to isolate the exact limit.
                $classification = 'EXPECTED_BLOCK'
                $blockType = if ($exceedingLimitType) { "Microsoft-reported restriction (ExceedingLimitType = $exceedingLimitType)" } else { 'Other outbound sending restriction (e.g. message-rate limit, outbound spam, or malware detection)' }
            }
        }
        else {
            # Not restricted
            $classification = 'NO_BLOCK_FOUND'
            $evidence += "User is not currently restricted"
        }
        
        # Evidence summary
        if ($trace.Success) {
            $evidence += "Message trace: $($trace.TotalMessages) messages, $($trace.TotalRecipients) total recipients, $($trace.UniqueExternalRecipients) unique external"
        }
        
        if ($policy.Success) {
            $evidence += "Policy '$($policy.PolicyName)': Daily=$($policy.RecipientLimitPerDay), ExtHourly=$($policy.RecipientLimitExternalPerHour), IntHourly=$($policy.RecipientLimitInternalPerHour), Action=$($policy.ActionWhenThresholdReached)"
        }
        
        if ($restricted.Success -and $restricted.IsBlocked) {
            $evidence += "Restricted since: $($restricted.LastBlockedDateTime), Reason: $($restricted.Reason)"
            # Parse Microsoft's semicolon-delimited block-reason counters so they can be reconciled
            # with the trace-derived hourly numbers above.
            $reasonFields = [ordered]@{}
            foreach ($pair in ([string]$restricted.Reason -split ';')) {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2) { $reasonFields[$kv[0].Trim()] = $kv[1].Trim() }
            }
            $detailParts = @()
            if ($reasonFields['ExceedingLimitType']) { $detailParts += "ExceedingLimitType=$($reasonFields['ExceedingLimitType']) (this is the recipient limit was exceeded)" }
            if ($reasonFields['LastMessageRcptCount']) { $detailParts += "LastMessageRcptCount=$($reasonFields['LastMessageRcptCount']) (recipients on the message that triggered the block)" }
            if ($detailParts.Count -gt 0) {
                $evidence += "Block detail: $($detailParts -join '; ')"
            }
        }
        
        if ($alerts.Success -and $alerts.AlertsFound) {
            $evidence += "Defender alerts: $($alerts.AlertCount) alerts in last 30 days"
        }
        
        return [PSCustomObject]@{
            Classification = $classification
            BlockType = $blockType
            Evidence = $evidence
            AttentionNeededCount = $attentionNeededCount
            NoAttentionCount = $noAttentionCount
            MaxDailyRecipients = $maxDailyRecipients
            EffectiveDailyLimit = $effectiveDailyLimit
            SecuritySignals = $securitySignals
        }
    }
    catch {
        return [PSCustomObject]@{
            Classification = 'NO_BLOCK_FOUND'
            BlockType = $null
            Evidence = @()
            AttentionNeededCount = 0
            NoAttentionCount = 0
            SecuritySignals = @()
        }
    }
}
#endregion

#endregion

#region HTML Report Generation

#region Get-RrlHtmlReport
function Get-RrlHtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained interactive HTML report with a six-tab layout,
        verdict banner, KPI cards, a CSS daily-volume bar chart, and a searchable,
        sortable, paginated message-trace table. All dynamic content is injected as a
        single reportData JSON object and rendered client-side by embedded vanilla
        JavaScript (no external CDNs, fonts, or libraries).
    .NOTES
        READ-ONLY: This function performs no remote calls and emits no state-changing
        cmdlets. Any remediation guidance appears as descriptive text only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$RrlData,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    # ----- Build row-level arrays for the data tabs (guarded by each function's Success flag) -----
    $maxMessageRows = 5000

    $messageRows = @()
    $messagesTruncated = $false
    if ($RrlData.MessageTrace.Success -and $RrlData.MessageTrace.RawMessages) {
        $rawAll = @($RrlData.MessageTrace.RawMessages)
        if ($rawAll.Count -gt $maxMessageRows) { $messagesTruncated = $true }
        $messageRows = @($rawAll | Sort-Object Received -Descending | Select-Object -First $maxMessageRows | ForEach-Object {
            [PSCustomObject]@{
                received       = if ($_.Received) { $_.Received.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                sender         = [string]$_.SenderAddress
                recipient      = [string]$_.RecipientAddress
                subject        = [string]$_.Subject
                status         = [string]$_.Status
                messageId      = [string]$_.MessageId
                messageTraceId = [string]$_.MessageTraceId
                fromIP         = [string]$_.FromIP
                toIP           = [string]$_.ToIP
                size           = [string]$_.Size
                isExternal     = [bool]$_.IsExternal
                traceDetails   = @(if ($_.PSObject.Properties['TraceDetails'] -and $_.TraceDetails) { $_.TraceDetails | ForEach-Object { [PSCustomObject]@{ date = [string]$_.Date; event = [string]$_.Event; detail = [string]$_.Detail } } })
            }
        })
    }

    $dailyRows = @()
    if ($RrlData.MessageTrace.Success -and $RrlData.MessageTrace.DailyStats) {
        $dailyRows = @(ConvertTo-RrlRows -Source $RrlData.MessageTrace.DailyStats -Map @(
            @('date', 'Date'), @('total', 'TotalRecipients', 'int'), @('external', 'ExternalRecipients', 'int'),
            @('internal', 'InternalRecipients', 'int'), @('messages', 'Messages', 'int'),
            @('delivered', 'Delivered', 'int'), @('failed', 'Failed', 'int'), @('filteredAsSpam', 'FilteredAsSpam', 'int')
        ))
    }

    $domainRows = @()
    if ($RrlData.MessageTrace.Success -and $RrlData.MessageTrace.TopRecipientDomains) {
        $domainRows = @(ConvertTo-RrlRows -Source $RrlData.MessageTrace.TopRecipientDomains -Map @(
            @('domain', 'Domain'), @('count', 'Count', 'int')
        ))
    }

    $statusRows = @()
    if ($RrlData.MessageTrace.Success -and $RrlData.MessageTrace.StatusBreakdown) {
        $statusRows = @(ConvertTo-RrlRows -Source $RrlData.MessageTrace.StatusBreakdown -Map @(
            @('status', 'Status'), @('count', 'Count', 'int')
        ))
    }

    $alertRows = @()
    if ($RrlData.DefenderAlerts.Success -and $RrlData.DefenderAlerts.Alerts) {
        $alertRows = @(ConvertTo-RrlRows -Source $RrlData.DefenderAlerts.Alerts -Map @(
            @('creationDate', 'CreationDate', 'date'), @('alertName', 'AlertName'), @('severity', 'Severity'),
            @('category', 'Category'), @('status', 'Status'), @('alertId', 'AlertId'), @('description', 'Description'),
            @('userPrincipalName', 'UserPrincipalName'), @('userDisplayName', 'UserDisplayName'),
            @('userAccountEnabled', 'UserAccountEnabled'), @('deviceName', 'DeviceName'), @('ipAddress', 'IPAddress'),
            @('alertWebUrl', 'AlertWebUrl'), @('classification', 'Classification'), @('determination', 'Determination'),
            @('detectionSource', 'DetectionSource'), @('serviceSource', 'ServiceSource'), @('providerAlertId', 'ProviderAlertId'),
            @('threatFamilyName', 'ThreatFamilyName'), @('threatDisplayName', 'ThreatDisplayName'), @('actorDisplayName', 'ActorDisplayName'),
            @('assignedTo', 'AssignedTo'), @('incidentId', 'IncidentId'), @('incidentWebUrl', 'IncidentWebUrl'),
            @('firstActivity', 'FirstActivity', 'date'), @('lastActivity', 'LastActivity', 'date'), @('lastUpdate', 'LastUpdate', 'date'),
            @('resolvedDateTime', 'ResolvedDateTime', 'date'), @('mitreTechniques', 'MitreTechniques'),
            @('evidenceCount', 'EvidenceCount', 'int'), @('evidenceSummary', 'EvidenceSummary'),
            @('recommendedActions', 'RecommendedActions'), @('comments', 'Comments'), @('tenantId', 'TenantId')
        ))
    }

    $sendAsRows = @()
    if ($RrlData.SendAsLogs.Success -and $RrlData.SendAsLogs.Entries) {
        $sendAsRows = @(ConvertTo-RrlRows -Source $RrlData.SendAsLogs.Entries -Map @(
            @('creationTime', 'CreationTime', 'date'), @('operation', 'Operation'), @('userId', 'UserId'),
            @('sendAsUserSmtp', 'SendAsUserSmtp'), @('sendOnBehalfOfUserSmtp', 'SendOnBehalfOfUserSmtp'),
            @('mailboxOwnerUpn', 'MailboxOwnerUPN'), @('clientIP', 'ClientIP'), @('subject', 'Subject'),
            @('internetMessageId', 'InternetMessageId'),
            @('resultStatus', 'ResultStatus'), @('workload', 'Workload')
        ))
    }

    $ruleRows = @()
    if ($RrlData.AccountHealth.Success -and $RrlData.AccountHealth.SecuritySignalsRules) {
        $ruleRows = @($RrlData.AccountHealth.SecuritySignalsRules | ForEach-Object {
            [PSCustomObject]@{
                name          = [string]$_.Name
                enabled       = [string]$_.Enabled
                forwardTo     = ($_.ForwardTo -join '; ')
                redirectTo    = ($_.RedirectTo -join '; ')
                deleteMessage = [string]$_.DeleteMessage
                description   = [string]$_.Description
                priority      = [string]$_.Priority
                mailboxOwnerId = [string]$_.MailboxOwnerId
            }
        })
    }

    $externalRecipients = @()
    if ($RrlData.MessageTrace.Success -and $RrlData.MessageTrace.ExternalRecipientsList) {
        $externalRecipients = @($RrlData.MessageTrace.ExternalRecipientsList)
    }

    $delegationRows = @()
    if ($RrlData.SecuritySignals -and $RrlData.SecuritySignals.DelegationEntries) {
        $delegationRows = @(ConvertTo-RrlRows -Source $RrlData.SecuritySignals.DelegationEntries -Map @(
            @('permissionType', 'PermissionType'), @('user', 'User'), @('accessRights', 'AccessRights'),
            @('accessControlType', 'AccessControlType'), @('deny', 'Deny'), @('inheritanceType', 'InheritanceType')
        ))
    }

    # ----- Assemble the reportData object injected into the page -----
    $reportData = @{
        affectedUser      = $UserPrincipalName
        displayName       = if ($RrlData.Recipient.Success) { $RrlData.Recipient.DisplayName } else { '' }
        recipientType     = if ($RrlData.Recipient.Success) { $RrlData.Recipient.RecipientTypeDetails } else { '' }
        reportTimestamp   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        analysisTimestamp = $RrlData.AnalysisTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
        lookbackDays      = $RrlData.LookbackDays

        verdict = @{
            classification     = $RrlData.Verdict.Classification
            blockType          = [string]$RrlData.Verdict.BlockType
            evidence           = @($RrlData.Verdict.Evidence)
            attentionNeededCount = $RrlData.Verdict.AttentionNeededCount
            noAttentionCount     = $RrlData.Verdict.NoAttentionCount
            maxDaily           = $RrlData.Verdict.MaxDailyRecipients
            effectiveLimit     = $RrlData.Verdict.EffectiveDailyLimit
            securitySignals = @($RrlData.Verdict.SecuritySignals | ForEach-Object {
                [PSCustomObject]@{
                    name      = [string]$_.Name
                    condition = [string]$_.Condition
                    met       = [bool]$_.Met
                    detail    = [string]$_.Detail
                    detailType = [string]$_.DetailType
                    entries   = @($_.Entries | ForEach-Object {
                        [PSCustomObject]@{
                            target        = [string]$_.Target
                            source        = [string]$_.Source
                            matchedDomain = [string]$_.MatchedDomain
                            subject       = [string]$_.Subject
                            messageCount  = if ($null -ne $_.MessageCount) { [int]$_.MessageCount } else { $null }
                            percentage    = if ($null -ne $_.Percentage) { [double]$_.Percentage } else { $null }
                            sentDateTime  = [string]$_.SentDateTime
                            name          = [string]$_.Name
                            value         = [string]$_.Value
                        }
                    })
                    messages  = @($_.Messages | ForEach-Object {
                        [PSCustomObject]@{
                            messageId       = [string]$_.MessageId
                            senderAddress   = [string]$_.SenderAddress
                            recipientAddress = [string]$_.RecipientAddress
                            subject         = [string]$_.Subject
                            type            = [string]$_.Type
                            entityType      = [string]$_.EntityType
                            policyType      = [string]$_.PolicyType
                            policyName      = [string]$_.PolicyName
                            quarantineTypes = [string]$_.QuarantineTypes
                            releaseStatus   = [string]$_.ReleaseStatus
                            receivedTime    = [string]$_.ReceivedTime
                            systemReleased  = [string]$_.SystemReleased
                            expires         = [string]$_.Expires
                            reported        = [string]$_.Reported
                        }
                    })
                }
            })
        }

        restricted = @{
            isBlocked     = if ($RrlData.RestrictedEntity.Success) { [bool]$RrlData.RestrictedEntity.IsBlocked } else { $false }
            lookupFailed  = if ($RrlData.RestrictedEntity.Success) { $false } else { $true }
            error         = if ($RrlData.RestrictedEntity.Success) { $null } else { [string]$RrlData.RestrictedEntity.Error }
            blockedSender = if ($RrlData.RestrictedEntity.Success -and $RrlData.RestrictedEntity.IsBlocked) { $RrlData.RestrictedEntity.BlockedSenderAddress } else { $null }
            timestamp     = if ($RrlData.RestrictedEntity.Success -and $RrlData.RestrictedEntity.IsBlocked) { [string]$RrlData.RestrictedEntity.LastBlockedDateTime } else { $null }
            reason        = if ($RrlData.RestrictedEntity.Success -and $RrlData.RestrictedEntity.IsBlocked) { $RrlData.RestrictedEntity.Reason } else { $null }
            identity      = if ($RrlData.RestrictedEntity.Success -and $RrlData.RestrictedEntity.IsBlocked) { $RrlData.RestrictedEntity.Identity } else { $null }
        }

        policy = @{
            name                = if ($RrlData.Policy.Success) { $RrlData.Policy.PolicyName } else { 'Unknown' }
            dailyLimit          = if ($RrlData.Policy.Success) { $RrlData.Policy.RecipientLimitPerDay } else { 0 }
            externalHourlyLimit = if ($RrlData.Policy.Success) { $RrlData.Policy.RecipientLimitExternalPerHour } else { 0 }
            internalHourlyLimit = if ($RrlData.Policy.Success) { $RrlData.Policy.RecipientLimitInternalPerHour } else { 0 }
            action              = if ($RrlData.Policy.Success) { $RrlData.Policy.ActionWhenThresholdReached } else { 'Unknown' }
            autoForwarding      = if ($RrlData.Policy.Success) { $RrlData.Policy.AutoForwardingMode } else { 'Unknown' }
        }

        trace = @{
            totalMessages   = if ($RrlData.MessageTrace.Success) { $RrlData.MessageTrace.TotalMessages } else { 0 }
            totalRecipients = if ($RrlData.MessageTrace.Success) { $RrlData.MessageTrace.TotalRecipients } else { 0 }
            uniqueExternal  = if ($RrlData.MessageTrace.Success) { $RrlData.MessageTrace.UniqueExternalRecipients } else { 0 }
            internalCount   = if ($RrlData.MessageTrace.Success) { $RrlData.MessageTrace.InternalRecipientsCount } else { 0 }
            peakRolling60   = if ($RrlData.MessageTrace.Success) { $RrlData.MessageTrace.PeakRolling60Min } else { 0 }
            maxDaily        = $RrlData.Verdict.MaxDailyRecipients
            effectiveLimit  = $RrlData.Verdict.EffectiveDailyLimit
            truncated       = $messagesTruncated
            daily           = $dailyRows
            topDomains      = $domainRows
            statusBreakdown = $statusRows
            messages        = $messageRows
            externalList    = $externalRecipients
        }

        alerts = @{
            count   = if ($RrlData.DefenderAlerts.Success) { $RrlData.DefenderAlerts.AlertCount } else { 0 }
            found   = if ($RrlData.DefenderAlerts.Success) { [bool]$RrlData.DefenderAlerts.AlertsFound } else { $false }
            skipped = if ($RrlData.DefenderAlerts.Success -and $RrlData.DefenderAlerts.Skipped) { $true } else { $false }
            list    = $alertRows
        }

        sendas = @{
            count   = if ($RrlData.SendAsLogs.Success) { $RrlData.SendAsLogs.Count } else { 0 }
            found   = if ($RrlData.SendAsLogs.Success) { [bool]$RrlData.SendAsLogs.Found } else { $false }
            skipped = if ($RrlData.SendAsLogs.Success -and $RrlData.SendAsLogs.Skipped) { $true } else { $false }
            error   = if ($RrlData.SendAsLogs.Success) { $null } else { [string]$RrlData.SendAsLogs.Error }
            list    = $sendAsRows
        }

        health = @{
            externalForward         = if ($RrlData.AccountHealth.Success) { [bool]$RrlData.AccountHealth.HasExternalForward } else { $false }
            forwardingAddress       = if ($RrlData.AccountHealth.Success) { [string]$RrlData.AccountHealth.ForwardingAddress } else { '' }
            deliverAndForward       = if ($RrlData.AccountHealth.Success) { [string]$RrlData.AccountHealth.DeliverToMailboxAndForward } else { '' }
            securitySignalsRulesCount    = $ruleRows.Count
            securitySignalsRules         = $ruleRows
            delegationEntries       = $delegationRows
        }
    }

    $reportDataJson = $reportData | ConvertTo-Json -Depth 12 -Compress

    # ----- Static HTML skeleton. Only $reportDataJson is injected; all rendering is done in JS. -----
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sender Restriction Analysis Report</title>
    <style>
    :root{
        --primary:#3e97ff;--primary-2:#7239ea;
        --grad-a:#667eea;--grad-b:#764ba2;
        --success:#2ecc71;--success-2:#16a34a;
        --warning:#f39c12;--warning-2:#e67e22;
        --danger:#e74c3c;--danger-2:#c0392b;
        --info:#64748b;
        --bg:#f5f7fa;--bg-2:#c3cfe2;
        --surface:#ffffff;--text:#1e293b;--text-muted:#64748b;--border:#e2e8f0;
        --shadow:0 2px 4px rgba(0,0,0,.08);--shadow-lg:0 4px 20px rgba(0,0,0,.1);
    }
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Inter','Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;background:linear-gradient(135deg,var(--bg) 0%,var(--bg-2) 100%);min-height:100vh;color:var(--text);padding-left:265px;line-height:1.5;}
    @media(max-width:992px){body{padding-left:0;}}
    .confidential-banner{background:linear-gradient(135deg,var(--danger) 0%,var(--danger-2) 100%);color:#fff;text-align:center;padding:10px 12px;font-weight:600;font-size:13px;letter-spacing:.3px;}
    /* Sidebar (Metronic-style light sidebar) */
    .sidebar{position:fixed;left:0;top:0;width:265px;height:100vh;background:#fff;color:#4b5675;z-index:1000;overflow-y:auto;overflow-x:hidden;transition:all .3s ease;box-shadow:0 0 28px 0 rgba(82,63,105,.05);border-right:1px solid #f1f1f4;display:flex;flex-direction:column;}
    .sidebar::-webkit-scrollbar{width:4px;}.sidebar::-webkit-scrollbar-thumb{background:#e1e3ea;border-radius:4px;}
    .sidebar-header{padding:16px 22px;display:flex;align-items:center;justify-content:space-between;height:70px;flex-shrink:0;border-bottom:1px solid #f1f1f4;}
    .sidebar-logo{display:flex;align-items:center;gap:10px;}
    .sidebar-logo-icon{width:38px;height:38px;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%);border-radius:9px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px;}
    .sidebar-logo-text{font-size:16px;font-weight:700;color:#071437;letter-spacing:-.3px;}
    .sidebar-close{display:none;background:none;border:none;color:#99a1b7;font-size:22px;cursor:pointer;width:28px;height:28px;border-radius:6px;line-height:1;}
    .sidebar-close:hover{background:#f1f1f4;color:#071437;}
    .sidebar-section-title{padding:16px 22px 8px;font-size:11px;font-weight:600;color:#99a1b7;text-transform:uppercase;letter-spacing:.5px;}
    .sidebar-nav{padding:4px 0;flex:1;}
    .sidebar-item{display:flex;align-items:center;gap:10px;padding:9px 22px;margin:1px 12px;color:#4b5675;text-decoration:none;transition:all .15s ease;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;position:relative;border:none;background:transparent;width:calc(100% - 24px);text-align:left;}
    .sidebar-item:hover{background:#f9f9f9;color:var(--primary);}
    .sidebar-item.active{background:#eef6ff;color:var(--primary);font-weight:600;}
    .sidebar-item.active::before{content:'';position:absolute;left:-12px;top:50%;transform:translateY(-50%);width:3px;height:22px;background:var(--primary);border-radius:0 3px 3px 0;}
    .sidebar-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0;}
    .sidebar-count{margin-left:auto;background:#eef2ff;color:var(--primary);border-radius:9px;padding:1px 8px;font-size:11px;font-weight:700;}
    .sidebar-item.active .sidebar-count{background:var(--primary);color:#fff;}
    .sidebar-footer{padding:16px;border-top:1px solid #f1f1f4;flex-shrink:0;}
    .sidebar-footer-card{background:linear-gradient(135deg,#f9f9f9 0%,#f1f1f4 100%);border-radius:10px;padding:14px;text-align:center;}
    .sidebar-footer-title{font-size:12px;font-weight:600;color:#071437;margin-bottom:4px;}
    .sidebar-footer-text{font-size:11px;color:#99a1b7;line-height:1.4;}
    .sidebar-toggle{position:fixed;left:16px;top:54px;z-index:999;background:#fff;color:#4b5675;border:1px solid #f1f1f4;width:40px;height:40px;border-radius:8px;font-size:18px;cursor:pointer;box-shadow:0 3px 12px rgba(82,63,105,.12);display:none;align-items:center;justify-content:center;}
    .sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.3);z-index:999;}
    @media(max-width:992px){.sidebar{transform:translateX(-100%);}.sidebar.open{transform:translateX(0);box-shadow:0 10px 30px rgba(0,0,0,.15);}.sidebar-toggle{display:flex;}.sidebar-close{display:flex;align-items:center;justify-content:center;}.sidebar-overlay.show{display:block;}}
    /* Layout */
    .dashboard{max-width:1280px;margin:0 auto;padding:24px;}
    .header{background:#fff;border-radius:16px;padding:22px 26px;margin-bottom:20px;box-shadow:var(--shadow);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px;}
    .header h1{font-size:23px;color:#2c3e50;margin-bottom:6px;display:flex;align-items:center;gap:10px;}
    .header .meta{color:var(--text-muted);font-size:13px;line-height:1.7;}
    .btn{background:#fff;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:var(--shadow);transition:all .2s;display:inline-flex;align-items:center;gap:6px;}
    .btn:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-1px);}
    .btn-primary{background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%);color:#fff;border:none;}
    .btn-primary:hover{color:#fff;opacity:.94;}
    /* KPI stat cards */
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:22px;}
    .stat-card{background:#fff;border-radius:12px;padding:18px 20px;box-shadow:var(--shadow);position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s;min-height:118px;display:flex;flex-direction:column;--accent:var(--primary);}
    .stat-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:var(--accent);}
    .stat-card:hover{transform:translateY(-4px);box-shadow:var(--shadow-lg);}
    .stat-card.success{--accent:var(--success);}.stat-card.warning{--accent:var(--warning);}.stat-card.danger{--accent:var(--danger);}
    .stat-icon{width:40px;height:40px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:12px;background:#eef2f7;color:var(--accent);}
    .stat-label{font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;}
    .stat-value{font-size:28px;font-weight:700;color:#2c3e50;line-height:1;}
    .stat-meta{font-size:12px;color:var(--text-muted);margin-top:8px;}
    /* Panels / sections */
    .panel{display:block;scroll-margin-top:16px;}
    .panel + .panel{margin-top:2px;}
    .section{background:#fff;border-radius:12px;margin-bottom:18px;box-shadow:var(--shadow);overflow:hidden;padding:0 22px 20px;}
    .section>h2{margin:0 -22px 16px;padding:16px 22px;font-size:16px;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--grad-a) 0%,var(--grad-b) 100%);display:flex;align-items:center;gap:10px;}
    .section h3{margin:16px 0 8px;font-size:14px;color:#2c3e50;}
    .kv{margin:6px 0;font-size:14px;display:flex;align-items:flex-start;gap:8px;}
    .kv strong{flex-shrink:0;min-width:190px;color:var(--text-muted);font-weight:600;word-break:break-word;}
    ul.list{margin:6px 0;padding-left:20px;}ul.list li{margin:4px 0;font-size:14px;}
    .score-wrap{display:flex;gap:20px;flex-wrap:wrap;}
    .score-box{flex:1;min-width:220px;}
    .bar-track{background:#eef0f4;border-radius:6px;height:12px;overflow:hidden;}
    .bar-fill{height:100%;border-radius:6px;}
    /* Tables */
    table{width:100%;border-collapse:collapse;font-size:13px;}
    th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;}
    thead th{position:sticky;top:0;background:linear-gradient(135deg,var(--grad-a) 0%,var(--grad-b) 100%);color:#fff;cursor:pointer;user-select:none;white-space:nowrap;font-weight:600;}
    th.sortable::after{content:' \2195';opacity:.75;font-size:11px;}
    th.sort-asc::after{content:' \2191';}
    th.sort-desc::after{content:' \2193';}
    tbody tr:hover{background:rgba(62,151,255,.06);}
    .badge{display:inline-block;border-radius:12px;padding:2px 10px;font-size:11px;font-weight:600;color:#fff;}
    .badge-ext{background:var(--warning);}.badge-int{background:var(--info);}
    .badge-Delivered{background:var(--success);}.badge-Failed{background:var(--danger);}.badge-FilteredAsSpam{background:var(--warning);}
    .badge-Quarantined{background:var(--primary-2);}
    .badge-High{background:var(--danger);}.badge-Medium{background:var(--warning);}.badge-Low{background:var(--info);}
    .table-controls{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;}
    .search-input{padding:9px 12px;border:1px solid var(--border);border-radius:8px;background:#fff;color:var(--text);min-width:240px;font-size:13px;}
    .table-scroll{overflow-x:auto;max-height:560px;overflow-y:auto;border:1px solid var(--border);border-radius:10px;}
    .pager{display:flex;gap:8px;align-items:center;margin-top:12px;font-size:13px;flex-wrap:wrap;}
    /* Chart */
    .chart{margin-top:8px;}
    .chart-row{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:12px;}
    .chart-label{width:96px;color:var(--text-muted);flex-shrink:0;}
    .chart-bar-wrap{flex:1;background:#eef0f4;border-radius:6px;position:relative;height:22px;}
    .chart-bar{height:100%;border-radius:6px;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%);}
    .chart-bar.over{background:linear-gradient(135deg,var(--danger) 0%,var(--danger-2) 100%);}
    .chart-val{width:60px;text-align:right;flex-shrink:0;font-weight:600;}
    .limit-line{position:absolute;top:-3px;bottom:-3px;width:2px;background:var(--danger);}
    .muted{color:var(--text-muted);}
    .empty{padding:24px;text-align:center;color:var(--text-muted);font-style:italic;}
    .guidance{background:#eef6ff;border-left:3px solid var(--primary);padding:12px 16px;border-radius:8px;font-size:13px;margin-top:12px;color:#334155;}
    .recommendation-options{display:grid;gap:12px;margin:16px 0;}
    .recommendation-option{border:1px solid var(--border);border-radius:8px;background:#fff;overflow:hidden;}
    .recommendation-option summary{display:flex;align-items:center;gap:12px;padding:16px;cursor:pointer;list-style:none;background:#f8fafc;color:#1e293b;font-size:14px;font-weight:700;user-select:none;}
    .recommendation-option summary::-webkit-details-marker{display:none;}
    .recommendation-option summary:hover{background:#eef6ff;}
    .recommendation-option summary:focus-visible{outline:2px solid var(--primary);outline-offset:-2px;}
    .recommendation-option summary::after{content:'\002B';margin-left:auto;width:24px;height:24px;display:flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:6px;background:#fff;color:var(--primary);font-size:18px;font-weight:600;line-height:1;flex-shrink:0;}
    .recommendation-option[open] summary{border-bottom:1px solid var(--border);background:#eef6ff;}
    .recommendation-option[open] summary::after{content:'\2212';}
    .recommendation-number{display:flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:6px;background:var(--primary);color:#fff;font-size:13px;flex-shrink:0;}
    .recommendation-content{padding:4px 16px 16px;}
    /* Message groups (grouped message trace) */
    .mv-card{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden;background:#fff;}
    .mv-header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;padding:14px 16px;cursor:pointer;background:#f8fafc;transition:background .15s ease;flex-wrap:wrap;}
    .mv-header:hover{background:#eef6ff;}
    .mv-header-main{min-width:220px;flex:1;}
    .mv-subject{font-weight:600;font-size:14px;color:#1e293b;word-break:break-word;}
    .mv-sub{font-size:12px;color:var(--text-muted);margin-top:2px;}
    .mv-header-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end;}
    .mv-date{font-size:11px;color:var(--text-muted);width:100%;text-align:right;margin-top:2px;}
    .mv-body{display:none;padding:12px 16px;border-top:1px solid var(--border);background:#fff;}
    .mv-body.show{display:block;}
    .mv-ids{margin-bottom:10px;padding:10px 12px;background:#f8fafc;border:1px solid var(--border);border-radius:8px;}
    .mv-ids .kv strong{min-width:140px;}
    .mt-row{cursor:pointer;}
    .mt-caret{color:var(--text-muted);font-size:11px;}
    .mt-detail-content{display:none;padding:14px 16px;background:#f8fafc;}
    .mt-detail-content.show{display:block;}
    /* Event flow timeline */
    .ef-wrap{padding:2px 2px;}
    .ef-title{display:flex;align-items:center;gap:8px;font-weight:700;font-size:14px;color:#1e293b;margin-bottom:12px;}
    .ef-flow{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:18px;}
    .ef-pill{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;padding:4px 10px;border-radius:6px;}
    .ef-arrow{color:#cbd5e1;font-size:12px;}
    .ef-timeline{position:relative;padding-left:6px;}
    .ef-timeline::before{content:'';position:absolute;left:5px;top:6px;bottom:6px;width:2px;background:#e2e8f0;}
    .ef-item{position:relative;padding:0 0 16px 22px;}
    .ef-item:last-child{padding-bottom:2px;}
    .ef-dot{position:absolute;left:0;top:3px;width:11px;height:11px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 0 1px #e2e8f0;}
    .ef-event{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px;}
    .ef-detail{font-size:13px;color:#334155;font-weight:500;word-break:break-word;}
    .ef-date{font-size:11px;color:#94a3b8;margin-top:2px;}
    /* Mailbox Security Insights overview (donut) + cards */
    .si-overview{display:flex;align-items:center;gap:26px;flex-wrap:wrap;background:linear-gradient(135deg,#ffffff 0%,#fbfcfe 100%);border:1px solid #eef2f7;border-radius:14px;padding:20px 24px;margin-bottom:18px;}
    .si-overview svg{flex-shrink:0;}
    .si-overview-text{min-width:220px;flex:1;}
    .si-title{font-size:16px;font-weight:700;color:#2c3e50;margin-bottom:4px;}
    .si-sub{font-size:13px;color:var(--text-muted);margin-bottom:12px;line-height:1.5;}
    .si-badges{display:flex;gap:8px;flex-wrap:wrap;}
    .count-badge{padding:5px 12px;border-radius:8px;font-size:12px;font-weight:600;border:2px solid #cbd5e1;color:#334155;}
    .count-badge.passed{border-color:#27ae60;color:#1a7a43;}
    .count-badge.failed{border-color:#e74c3c;color:#b53225;}
    .count-badge.total{border-color:#3e97ff;color:#2b6fc2;}
    .ind-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;}
    .ind-card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow);transition:transform .2s,box-shadow .2s;}
    .ind-card:hover{transform:translateY(-3px);box-shadow:var(--shadow-lg);}
    .ind-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;}
    .ind-name{font-size:14px;font-weight:600;color:#2c3e50;}
    .ind-badge{color:#fff;padding:3px 12px;border-radius:12px;font-size:12px;font-weight:700;flex-shrink:0;}
    .ind-condition{font-size:12px;color:#94a3b8;margin-bottom:10px;line-height:1.5;}
    .ind-progress{height:8px;background:#ecf0f1;border-radius:4px;overflow:hidden;margin-bottom:8px;}
    .ind-bar{height:100%;border-radius:4px;width:100%;}
    .ind-meta{display:flex;justify-content:space-between;font-size:12px;color:var(--text-muted);margin-top:8px;}
    .ind-detail{font-size:12px;color:#475569;line-height:1.5;}
    .ind-card.clickable{cursor:pointer;}
    .ind-click{text-align:center;margin-top:10px;font-size:12px;color:#7f8c8d;font-weight:500;}
    /* Footer */
    footer.report-footer{background:linear-gradient(135deg,#2c3e50 0%,#34495e 100%);color:#fff;padding:22px;text-align:center;margin-top:30px;border-radius:16px;border-top:4px solid var(--primary);}
    footer.report-footer .f-title{font-size:15px;font-weight:600;margin-bottom:6px;}
    footer.report-footer .f-sub{font-size:12px;color:#bdc3c7;}
    @media print{.sidebar,.sidebar-toggle,.btn,.table-controls,.pager{display:none !important;}body{padding-left:0;background:#fff;}.panel{display:block !important;}.table-scroll{max-height:none;overflow:visible;}}
    /* Alert details modal */
    .modal-overlay{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:1000;align-items:flex-start;justify-content:center;padding:40px 16px;overflow-y:auto;}
    .modal-box{background:#fff;border-radius:14px;max-width:820px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.35);overflow:hidden;}
    .modal-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 22px;background:linear-gradient(135deg,#2c3e50 0%,#34495e 100%);color:#fff;}
    .modal-head h3{margin:0;font-size:16px;font-weight:600;word-break:break-word;}
    .modal-close{background:transparent;border:none;color:#fff;font-size:26px;line-height:1;cursor:pointer;padding:0 4px;}
    .modal-close:hover{color:#e74c3c;}
    .modal-body{padding:20px 22px;max-height:70vh;overflow-y:auto;}
    .modal-detail-table th{border-bottom:1px solid var(--border);}
    .modal-detail-table td{border-bottom:1px solid var(--border);}
    </style>
</head>
<body>
    <button class="sidebar-toggle" onclick="toggleSidebar()" aria-label="Toggle navigation">&#9776;</button>
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>
    <aside class="sidebar" id="rrlSidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <div class="sidebar-logo-icon">SRA</div>
                <div class="sidebar-logo-text">Sender Restriction Analyzer</div>
            </div>
            <button class="sidebar-close" onclick="toggleSidebar()" aria-label="Close">&times;</button>
        </div>
        <div class="sidebar-section-title">Analysis</div>
        <nav class="sidebar-nav" id="sidebarNav"></nav>
        <div class="sidebar-footer">
            <div class="sidebar-footer-card">
                <div class="sidebar-footer-title">&#128274; Confidential</div>
                <div class="sidebar-footer-text">The report contains UPNs, recipient addresses, message metadata, and security insights. Do not distribute unencrypted</div>
            </div>
        </div>
    </aside>

    <div class="confidential-banner">CONFIDENTIAL &mdash; Contains UPNs, recipient addresses, message metadata, and security insights. Do not distribute unencrypted.</div>
    <div class="dashboard">
        <div class="header">
            <div>
                <h1><span>&#128231;</span> Sender Restriction Analyzer Report</h1>
                <div class="meta" id="headerMeta"></div>
            </div>
            <div>
                <button class="btn btn-primary" id="copyVerdictSummary" type="button">&#128203; Copy Verdict Summary</button>
            </div>
        </div>

        <div class="stats-grid" id="kpiGrid"></div>

        <div id="panels">
            <div class="panel" id="panel-verdict" role="tabpanel"></div>
            <div class="panel" id="panel-restricted" role="tabpanel"></div>
            <div class="panel" id="panel-policy" role="tabpanel"></div>
            <div class="panel" id="panel-trace" role="tabpanel"></div>
            <div class="panel" id="panel-alerts" role="tabpanel"></div>
            <div class="panel" id="panel-sendas" role="tabpanel"></div>
            <div class="panel" id="panel-indicators" role="tabpanel"></div>
            <div class="panel" id="panel-recommendations" role="tabpanel"></div>
        </div>

        <footer id="footer" class="report-footer"></footer>
    </div>

    <script>
        var reportData = $reportDataJson;

        function esc(v) {
            if (v === null || v === undefined) { return ''; }
            return String(v)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        function el(id) { return document.getElementById(id); }
        function num(v) { return (v === null || v === undefined) ? 0 : Number(v); }

        // ---------- Clipboard ----------
        function copyText(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () { flash('Copied to clipboard'); },
                    function () { legacyCopy(text); });
            } else { legacyCopy(text); }
        }
        function legacyCopy(text) {
            var ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.focus(); ta.select();
            try { document.execCommand('copy'); flash('Copied to clipboard'); } catch (e) { flash('Copy failed'); }
            document.body.removeChild(ta);
        }
        function flash(msg) {
            var d = document.createElement('div');
            d.textContent = msg;
            d.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#323130;color:#fff;padding:8px 16px;border-radius:4px;z-index:9999;font-size:13px;';
            document.body.appendChild(d);
            setTimeout(function () { document.body.removeChild(d); }, 1600);
        }

        // ---------- Header + KPIs ----------
        function renderHeader() {
            el('headerMeta').innerHTML =
                'User: <strong>' + esc(reportData.affectedUser) + '</strong> (' + esc(reportData.displayName) + ', ' + esc(reportData.recipientType) + ')<br>' +
                'Generated: ' + esc(reportData.reportTimestamp) + ' &middot; Lookback: ' + esc(reportData.lookbackDays) + ' day(s)';
            el('footer').innerHTML = '<div class="f-title">Sender Restriction Analyzer \u2014 Recipient Rate Limit (RRL) Analysis</div>' +
                '<div class="f-sub">Report generated ' + esc(reportData.reportTimestamp) + ' \u2014 Read-only analysis; no changes were made to the tenant.</div>';
        }
        function kpiCard(icon, label, value, meta, cls) {
            return '<div class="stat-card ' + (cls || '') + '"><div class="stat-icon">' + icon + '</div><div class="stat-label">' + esc(label) +
                '</div><div class="stat-value">' + esc(value) + '</div><div class="stat-meta">' + esc(meta) + '</div></div>';
        }
        function renderKpis() {
            var t = reportData.trace || {}, r = reportData.restricted || {}, a = reportData.alerts || {};
            var limit = num(t.effectiveLimit);
            var pct = limit > 0 ? Math.round((num(t.maxDaily) / limit) * 100) : 0;
            var html = '';
            html += kpiCard('&#128274;', 'Restriction Status',
                r.isBlocked ? 'Blocked' : (r.lookupFailed ? 'Unknown' : 'Active'),
                r.isBlocked ? ('Since ' + (r.timestamp || 'unknown')) : (r.lookupFailed ? 'Lookup failed \u2014 verify manually' : 'Not restricted'),
                r.isBlocked ? 'danger' : (r.lookupFailed ? 'warning' : 'success'));
            html += kpiCard('&#128200;', 'Peak Daily Recipients', num(t.maxDaily), 'of ' + limit + ' daily limit (' + pct + '%)',
                pct >= 100 ? 'danger' : (pct >= 80 ? 'warning' : ''));
            html += kpiCard('&#128231;', 'Messages', num(t.totalMessages), num(t.totalRecipients) + ' recipient rows', '');
            html += kpiCard('&#128737;', 'Defender Alerts', num(a.count), a.skipped ? 'Skipped' : 'Last 30 days', num(a.count) > 0 ? 'warning' : 'success');
            el('kpiGrid').innerHTML = html;
        }

        // ---------- Tabs ----------
        var TABS = [
            { id: 'verdict',    icon: '&#128203;', label: 'Verdict & Summary', count: null },
            { id: 'restricted', icon: '&#128274;', label: 'Restricted Entity', count: function () { return reportData.restricted.isBlocked ? 'Yes' : 'No'; } },
            { id: 'policy',     icon: '&#128203;', label: 'Outbound Spam Policy', count: null },
            { id: 'volume',     icon: '&#128202;', label: 'Volume Overview',   count: null, anchor: 'section-volume' },
            { id: 'trace',      icon: '&#128233;', label: 'Message Trace',     count: function () { return (reportData.trace.messages || []).length; }, anchor: 'section-messagetrace' },
            { id: 'alerts',     icon: '&#128737;', label: 'Defender Alerts',    count: function () { return (reportData.alerts.list || []).length; } },
            { id: 'sendas',     icon: '&#128232;', label: 'SendAs Logs',        count: function () { return (reportData.sendas.list || []).length; } },
            { id: 'indicators', icon: '&#9888;',   label: 'Mailbox Security Insights', count: function () { var inds = (reportData.verdict && reportData.verdict.securitySignals) || []; var n = 0; for (var i = 0; i < inds.length; i++) { if (inds[i].met) { n++; } } return n; } },
            { id: 'recommendations', icon: '&#128161;', label: 'Recommendations', count: null }
        ];
        function renderTabs() {
            var nav = el('sidebarNav'), html = '';
            for (var i = 0; i < TABS.length; i++) {
                var tb = TABS[i];
                var c = tb.count ? tb.count() : null;
                html += '<button class="sidebar-item' + (i === 0 ? ' active' : '') + '" type="button" data-tab="' + tb.id + '">' +
                    '<span class="sidebar-icon">' + tb.icon + '</span><span>' + esc(tb.label) + '</span>' +
                    (c !== null ? '<span class="sidebar-count">' + c + '</span>' : '') + '</button>';
            }
            nav.innerHTML = html;
            var btns = nav.querySelectorAll('.sidebar-item');
            for (var j = 0; j < btns.length; j++) {
                btns[j].addEventListener('click', function () { activateTab(this.getAttribute('data-tab')); });
            }
            window.addEventListener('scroll', scrollSpy, { passive: true });
        }
        function setActiveNav(id) {
            var btns = document.querySelectorAll('.sidebar-item');
            for (var i = 0; i < btns.length; i++) {
                var on = btns[i].getAttribute('data-tab') === id;
                btns[i].className = 'sidebar-item' + (on ? ' active' : '');
            }
        }
        function tabById(id) {
            for (var i = 0; i < TABS.length; i++) { if (TABS[i].id === id) { return TABS[i]; } }
            return null;
        }
        function activateTab(id) {
            setActiveNav(id);
            var tb = tabById(id);
            var target = (tb && tb.anchor) ? el(tb.anchor) : el('panel-' + id);
            if (target) { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
            if (window.innerWidth <= 992) { closeSidebar(); }
        }
        function scrollSpy() {
            var current = TABS[0].id;
            for (var i = 0; i < TABS.length; i++) {
                var target = TABS[i].anchor ? el(TABS[i].anchor) : el('panel-' + TABS[i].id);
                if (target && target.getBoundingClientRect().top <= 120) { current = TABS[i].id; }
            }
            setActiveNav(current);
        }
        function toggleSidebar() {
            var s = el('rrlSidebar'), o = el('sidebarOverlay');
            if (s.classList.contains('open')) { s.classList.remove('open'); o.classList.remove('show'); }
            else { s.classList.add('open'); o.classList.add('show'); }
        }
        function closeSidebar() {
            el('rrlSidebar').classList.remove('open');
            el('sidebarOverlay').classList.remove('show');
        }

        // ---------- Generic sortable/paginated table ----------
        function makeTable(container, columns, rows, opts) {
            opts = opts || {};
            var state = { sortKey: null, sortDir: 1, page: 1, pageSize: opts.pageSize || 25, filter: '' };

            var controls = document.createElement('div');
            controls.className = 'table-controls';
            var left = document.createElement('div');
            if (opts.searchable) {
                var input = document.createElement('input');
                input.className = 'search-input'; input.type = 'search'; input.placeholder = 'Search...';
                input.addEventListener('input', function () { state.filter = this.value.toLowerCase(); state.page = 1; draw(); });
                left.appendChild(input);
            }
            var right = document.createElement('div');
            if (opts.copyButton) {
                var cb = document.createElement('button');
                cb.className = 'btn'; cb.type = 'button'; cb.textContent = opts.copyButton;
                cb.addEventListener('click', function () { opts.onCopy(); });
                right.appendChild(cb);
            }
            controls.appendChild(left); controls.appendChild(right);
            container.appendChild(controls);

            var scroll = document.createElement('div');
            scroll.className = 'table-scroll';
            var table = document.createElement('table');
            var thead = document.createElement('thead');
            var htr = document.createElement('tr');
            for (var c = 0; c < columns.length; c++) {
                (function (col) {
                    var th = document.createElement('th');
                    th.textContent = col.label;
                    if (col.sortable !== false) {
                        th.className = 'sortable';
                        th.addEventListener('click', function () {
                            if (state.sortKey === col.key) { state.sortDir = -state.sortDir; }
                            else { state.sortKey = col.key; state.sortDir = 1; }
                            draw();
                        });
                    }
                    htr.appendChild(th);
                })(columns[c]);
            }
            thead.appendChild(htr); table.appendChild(thead);
            var tbody = document.createElement('tbody');
            table.appendChild(tbody);
            scroll.appendChild(table); container.appendChild(scroll);

            var pager = document.createElement('div');
            pager.className = 'pager'; container.appendChild(pager);

            function filtered() {
                if (!state.filter) { return rows; }
                return rows.filter(function (row) {
                    for (var i = 0; i < columns.length; i++) {
                        var val = row[columns[i].key];
                        if (val !== null && val !== undefined && String(val).toLowerCase().indexOf(state.filter) !== -1) { return true; }
                    }
                    return false;
                });
            }
            function sorted(data) {
                if (!state.sortKey) { return data; }
                var key = state.sortKey, dir = state.sortDir;
                return data.slice().sort(function (a, b) {
                    var x = a[key], y = b[key];
                    var nx = Number(x), ny = Number(y);
                    if (!isNaN(nx) && !isNaN(ny) && x !== '' && y !== '') { return (nx - ny) * dir; }
                    x = (x === null || x === undefined) ? '' : String(x).toLowerCase();
                    y = (y === null || y === undefined) ? '' : String(y).toLowerCase();
                    return (x < y ? -1 : (x > y ? 1 : 0)) * dir;
                });
            }
            function draw() {
                var ths = htr.querySelectorAll('th');
                for (var i = 0; i < ths.length; i++) {
                    if (columns[i].sortable === false) { continue; }
                    ths[i].className = 'sortable' + (state.sortKey === columns[i].key ? (state.sortDir === 1 ? ' sort-asc' : ' sort-desc') : '');
                }
                var data = sorted(filtered());
                var total = data.length;
                var pages = Math.max(1, Math.ceil(total / state.pageSize));
                if (state.page > pages) { state.page = pages; }
                var start = (state.page - 1) * state.pageSize;
                var slice = data.slice(start, start + state.pageSize);
                if (!slice.length) {
                    tbody.innerHTML = '<tr><td colspan="' + columns.length + '" class="empty">No matching rows.</td></tr>';
                } else {
                    var h = '';
                    for (var r = 0; r < slice.length; r++) {
                        h += '<tr>';
                        for (var c = 0; c < columns.length; c++) {
                            h += '<td>' + (columns[c].render ? columns[c].render(slice[r]) : esc(slice[r][columns[c].key])) + '</td>';
                        }
                        h += '</tr>';
                    }
                    tbody.innerHTML = h;
                }
                pager.innerHTML = '';
                var info = document.createElement('span');
                info.className = 'muted';
                info.textContent = total + ' row(s) \u2014 page ' + state.page + ' of ' + pages;
                var prev = document.createElement('button');
                prev.className = 'btn'; prev.type = 'button'; prev.textContent = 'Prev';
                prev.disabled = state.page <= 1;
                prev.addEventListener('click', function () { if (state.page > 1) { state.page--; draw(); } });
                var next = document.createElement('button');
                next.className = 'btn'; next.type = 'button'; next.textContent = 'Next';
                next.disabled = state.page >= pages;
                next.addEventListener('click', function () { if (state.page < pages) { state.page++; draw(); } });
                pager.appendChild(prev); pager.appendChild(next); pager.appendChild(info);
            }
            draw();
        }

        function statusBadge(s) {
            if (!s) { return ''; }
            var safe = String(s).replace(/[^A-Za-z]/g, '');
            return '<span class="badge badge-' + safe + '">' + esc(s) + '</span>';
        }

        // ---------- Panels ----------
        function renderVerdictPanel() {
            var v = reportData.verdict || {}, p = reportData.policy || {};
            var boldTitles = ['External recipients/hour', 'Internal recipients/hour', 'Message trace', 'Policy', 'Restricted since', 'Block detail', 'Defender alerts'];
            var evidence = (v.evidence || []).map(function (x) {
                var safe = esc(x).replace(/policy &quot;([^&]*)&quot;/g, 'policy &quot;<strong>$1</strong>&quot;');
                for (var bi = 0; bi < boldTitles.length; bi++) {
                    var t = esc(boldTitles[bi]);
                    if (safe.indexOf(t) === 0) { safe = '<strong>' + t + '</strong>' + safe.slice(t.length); break; }
                }
                return '<li>' + safe + '</li>';
            }).join('') || '<li class="muted">None recorded.</li>';
            var guidance = verdictGuidance(v.classification);
            el('panel-verdict').innerHTML =
                '<div class="section"><h2>Verdict</h2>' +
                '<div class="kv"><strong>Classification</strong> ' + esc(v.classification) + '</div>' +
                (v.blockType ? '<div class="kv"><strong>Block type</strong> ' + esc(v.blockType) + '</div>' : '') +
                '<h3>Key Findings</h3><ul class="list">' + evidence + '</ul>' +
                '<div class="guidance">' + guidance + '</div></div>';
        }
        function renderPolicyPanel() {
            var p = reportData.policy || {};
            el('panel-policy').innerHTML =
                '<div class="section"><h2>Outbound Spam Policy</h2>' +
                '<div class="kv"><strong>Policy name</strong> ' + esc(p.name) + '</div>' +
                '<div class="kv"><strong>Daily limit</strong> ' + esc(p.dailyLimit) + ' recipients</div>' +
                '<div class="kv"><strong>External hourly limit</strong> ' + esc(p.externalHourlyLimit) + '</div>' +
                '<div class="kv"><strong>Internal hourly limit</strong> ' + esc(p.internalHourlyLimit) + '</div>' +
                '<div class="kv"><strong>Action at threshold</strong> ' + esc(p.action) + '</div>' +
                '<div class="kv"><strong>Auto-forwarding</strong> ' + esc(p.autoForwarding) + '</div></div>';
        }
        function renderRecommendations() {
            return '<div class="section"><h2>Recommendations</h2>' +
                '<h3>Why the limit exists</h3>' +
                '<ul class="list">' +
                '<li>A normal Microsoft 365 user mailbox is meant for everyday person-to-person email, not for bulk or automated sending.</li>' +
                '<li>To keep everyone protected from spam and abuse, Microsoft enforces a <strong>Recipient Rate Limit (RRL)</strong>. A regular mailbox can send to about <strong>10,000 recipients per day</strong>, and there is also a limit of around <strong>30 messages per minute</strong>.</li>' +
                '<li>Once you exceed those limits, the mailbox is temporarily blocked from sending.</li>' +
                '</ul>' +
                '<h3>More reading</h3>' +
                '<ul class="list">' +
                '<li><a href="https://learn.microsoft.com/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits" target="_blank" rel="noopener">Exchange Online sending limits</a></li>' +
                '</ul>' +
                '<h3>What to do if you need to send more</h3>' +
                '<div style="margin:6px 0 10px;font-size:14px;">If you need to reach <strong>more than 10,000 recipients per day</strong> or send <strong>more than 30 messages per minute</strong>, move that traffic off your regular mailbox. You can choose one of the options below that fits what you are sending.</div>' +
                '<div class="recommendation-options">' +
                '<details class="recommendation-option"><summary><span class="recommendation-number">1</span><span>High Volume Email (HVE) for Microsoft 365</span></summary><div class="recommendation-content">' +
                '<div class="kv" style="margin:4px 0;">Use this for internal and line-of-business mail sent from your own apps, scripts, or devices such as printers and scanners &mdash; things like reports, statements, and notifications going to people inside and outside your company.</div>' +
                '<ul class="list">' +
                '<li>Ask your IT admin (whoever manages your Microsoft 365 tenant) to turn on the High Volume Email service.</li>' +
                '<li>Have them create a separate High Volume Email account for your app or device. Because it is separate from your normal mailbox, your everyday email keeps working even during large sends.</li>' +
                '<li>Update your app, script, or device to send through that account instead of your personal mailbox.</li>' +
                '<li>Run a small test send first, check that it arrives, then increase your volume.</li>' +
                '<li>More details: <a href="https://learn.microsoft.com/exchange/mail-flow-best-practices/high-volume-mails-m365" target="_blank" rel="noopener">High-volume email for Microsoft 365</a></li>' +
                '</ul></div></details>' +
                '<details class="recommendation-option"><summary><span class="recommendation-number">2</span><span>Azure Communication Services Email</span></summary><div class="recommendation-content">' +
                '<div class="kv" style="margin:4px 0;">A good fit for developers and applications sending large amounts of transactional email &mdash; sign-up confirmations, password resets, receipts &mdash; where you pay for what you use and no mailbox is involved.</div>' +
                '<ul class="list">' +
                '<li>Use an existing Azure subscription or create one.</li>' +
                '<li>Create an Email Communication Service resource and connect a verified sending domain (a free trial subdomain or your own domain).</li>' +
                '<li>Wire the connection details or SDK into your application to start sending.</li>' +
                '<li>More details: <a href="https://learn.microsoft.com/azure/communication-services/concepts/email/email-overview" target="_blank" rel="noopener">Azure Communication Services Email overview</a></li>' +
                '</ul></div></details>' +
                '<details class="recommendation-option"><summary><span class="recommendation-number">3</span><span>A dedicated bulk or marketing email provider</span></summary><div class="recommendation-content">' +
                '<div class="kv" style="margin:4px 0;">Worth considering for newsletters and marketing campaigns, where you also want subscriber lists, templates, unsubscribe handling, and delivery reports.</div>' +
                '<ul class="list">' +
                '<li>Pick an established bulk or marketing email platform.</li>' +
                '<li>Verify your sending domain and set up SPF, DKIM, and DMARC so your mail is trusted.</li>' +
                '<li>To follow best practices for email marketing, check <a href="https://learn.microsoft.com/dynamics365/customer-insights/journeys/get-ready-email-marketing" target="_blank" rel="noopener">the article</a>.</li>' +
                '</ul></div></details></div>' +
                '<div class="guidance">Note: keep everyday email on your normal mailbox, and move large or automated sending to a service built for it &mdash; High Volume Email, Azure Communication Services, or a bulk email provider &mdash; so you do not hit the Recipient Rate Limit.</div></div>';
        }
        function verdictGuidance(c) {
            if (c === 'EXPECTED_BLOCK_DAILY' || c === 'EXPECTED_BLOCK_HOURLY' || c === 'EXPECTED_BLOCK') {
                return 'This block appears expected: the mailbox is restricted for outbound sending. To unblock and remove users from Restricted entities page follow the steps in <a href="https://learn.microsoft.com/defender-office-365/outbound-spam-restore-restricted-users" target="_blank" rel="noopener">the article</a>.';
            }
            if (c === 'NO_BLOCK_FOUND') {
                return 'No active restriction was detected for this mailbox.';
            }
            return 'No active restriction was detected for this mailbox.';
        }

        function renderChart() {
            var daily = reportData.trace.daily || [];
            if (!daily.length) { return '<div class="empty">No daily volume data.</div>'; }
            var limit = num(reportData.trace.effectiveLimit);
            var max = limit;
            for (var i = 0; i < daily.length; i++) { if (num(daily[i].total) > max) { max = num(daily[i].total); } }
            if (max <= 0) { max = 1; }
            var limitPct = limit > 0 ? (limit / max) * 100 : -1;
            var rows = '';
            for (var d = 0; d < daily.length; d++) {
                var val = num(daily[d].total);
                var w = (val / max) * 100;
                var over = limit > 0 && val >= limit;
                rows += '<div class="chart-row"><div class="chart-label">' + esc(daily[d].date) + '</div>' +
                    '<div class="chart-bar-wrap">' +
                    '<div class="chart-bar' + (over ? ' over' : '') + '" style="width:' + w + '%;"></div>' +
                    (limitPct >= 0 ? '<div class="limit-line" style="left:' + limitPct + '%;" title="Daily limit"></div>' : '') +
                    '</div><div class="chart-val">' + val + '</div></div>';
            }
            var legend = limit > 0 ? '<div class="muted" style="font-size:12px;margin-top:6px;">Red line = daily limit (' + limit + '). Red bars meet or exceed the limit.</div>' : '';
            return '<div class="chart">' + rows + '</div>' + legend;
        }

        var messageGroups = [];
        function renderTracePanel() {
            var t = reportData.trace || {};
            var container = el('panel-trace');
            var head = '<div class="section" id="section-volume"><h2>Messages and Recipients Volume Overview</h2>' +
                '<div class="kv"><strong>Total messages</strong> ' + num(t.totalMessages) + '</div>' +
                '<div class="kv"><strong>Total recipient rows</strong> ' + num(t.totalRecipients) + '</div>' +
                '<div class="kv"><strong>Unique external recipients</strong> ' + num(t.uniqueExternal) + '</div>' +
                '<div class="kv"><strong>Peak daily recipients</strong> ' + num(t.maxDaily) + ' (limit ' + num(t.effectiveLimit) + ')</div>' +
                '<h3>Daily recipient volume</h3>' + renderChart() +
                (t.truncated ? '<div class="guidance">Message list truncated to the first ' + (t.messages || []).length + ' rows for report size. Aggregates above reflect the full dataset.</div>' : '') +
                '</div>';
            container.innerHTML = head +
                '<div class="section" id="section-messagetrace"><h2>Message Trace</h2>' +
                '<div class="table-controls">' +
                '<input type="search" class="search-input" id="mtSearch" placeholder="Search subject, sender, recipient, Message ID, Message Trace ID...">' +
                '<button class="btn" id="mtCopyExt" type="button">Copy external recipients</button>' +
                '</div>' +
                '<div class="muted" style="font-size:12px;margin-bottom:8px;">Messages grouped by subject. Click a subject to expand all recipients and delivery events.</div>' +
                '<div id="mtGroups"></div></div>';
            buildMessageGroups();
            renderMessageGroups('');
            var s = el('mtSearch');
            if (s) { s.addEventListener('input', function () { renderMessageGroups(this.value.toLowerCase()); }); }
            var cbtn = el('mtCopyExt');
            if (cbtn) { cbtn.addEventListener('click', function () { copyText((reportData.trace.externalList || []).join('\n')); }); }
        }
        function buildMessageGroups() {
            var msgs = (reportData.trace && reportData.trace.messages) || [];
            var map = {};
            var order = [];
            for (var i = 0; i < msgs.length; i++) {
                var m = msgs[i];
                var key = m.subject && m.subject.length ? m.subject : '(no subject)';
                if (!map[key]) {
                    map[key] = { subject: key, rows: [], senders: {}, external: 0, internal: 0, statuses: {}, first: null, last: null, messageIds: {}, traceIds: {} };
                    order.push(key);
                }
                var g = map[key];
                g.rows.push(m);
                if (m.sender) { g.senders[m.sender] = true; }
                if (m.messageId) { g.messageIds[m.messageId] = true; }
                if (m.messageTraceId) { g.traceIds[m.messageTraceId] = true; }
                if (m.isExternal) { g.external++; } else { g.internal++; }
                g.statuses[m.status] = (g.statuses[m.status] || 0) + 1;
                if (m.received) {
                    if (!g.first || m.received < g.first) { g.first = m.received; }
                    if (!g.last || m.received > g.last) { g.last = m.received; }
                }
            }
            messageGroups = order.map(function (k) { return map[k]; });
            messageGroups.sort(function (a, b) { return (b.last || '').localeCompare(a.last || ''); });
        }
        function renderMessageGroups(filter) {
            var host = el('mtGroups');
            if (!host) { return; }
            var groups = messageGroups;
            if (filter) {
                groups = messageGroups.filter(function (g) {
                    if (g.subject.toLowerCase().indexOf(filter) !== -1) { return true; }
                    return g.rows.some(function (r) {
                        return (r.sender || '').toLowerCase().indexOf(filter) !== -1 ||
                               (r.recipient || '').toLowerCase().indexOf(filter) !== -1 ||
                               (r.messageId || '').toLowerCase().indexOf(filter) !== -1 ||
                               (r.messageTraceId || '').toLowerCase().indexOf(filter) !== -1;
                    });
                });
            }
            if (!groups.length) { host.innerHTML = '<div class="empty">No messages match your search.</div>'; return; }
            var html = '';
            for (var i = 0; i < groups.length; i++) {
                var g = groups[i];
                var sender = Object.keys(g.senders)[0] || 'Unknown';
                var statusBadges = '';
                var sk = Object.keys(g.statuses);
                for (var s = 0; s < sk.length; s++) {
                    statusBadges += '<span class="badge badge-' + String(sk[s]).replace(/[^A-Za-z]/g, '') + '">' + esc(sk[s]) + ' ' + g.statuses[sk[s]] + '</span> ';
                }
                var dateRange = esc(g.first || '') + (g.last && g.last !== g.first ? ' \u2013 ' + esc(g.last) : '');
                html += '<div class="mv-card">' +
                    '<div class="mv-header" onclick="toggleMvBody(\'mvbody-' + i + '\')">' +
                    '<div class="mv-header-main">' +
                    '<div class="mv-subject">\u25B8 ' + esc(g.subject) + '</div>' +
                    '<div class="mv-sub">' + esc(sender) + ' \u2192 ' + g.rows.length + ' recipient(s)</div>' +
                    '</div>' +
                    '<div class="mv-header-meta">' +
                    '<span class="badge badge-ext">External ' + g.external + '</span> ' +
                    '<span class="badge badge-int">Internal ' + g.internal + '</span> ' +
                    statusBadges +
                    '<div class="mv-date">' + dateRange + '</div>' +
                    '</div></div>';
                var rows = g.rows.slice().sort(function (a, b) { return (b.received || '').localeCompare(a.received || ''); });
                var msgIdList = Object.keys(g.messageIds).join(', ') || 'n/a';
                var traceIdList = Object.keys(g.traceIds).join(', ') || 'n/a';
                var idSummary = '<div class="mv-ids">' +
                    '<div class="kv"><strong>Message ID</strong> ' + esc(msgIdList) + '</div>' +
                    '<div class="kv"><strong>Message Trace ID</strong> ' + esc(traceIdList) + '</div></div>';
                var body = '<div class="table-scroll"><table><thead><tr><th style="width:26px"></th><th>Received</th><th>Recipient</th><th>Status</th><th>Scope</th><th>From IP</th><th>To IP</th><th>Size</th></tr></thead><tbody>';
                for (var r = 0; r < rows.length; r++) {
                    var row = rows[r];
                    var detId = 'mtd-' + i + '-' + r;
                    var details = row.traceDetails || [];
                    body += '<tr class="mt-row" onclick="toggleMtDetail(\'' + detId + '\', this)">' +
                        '<td><span class="mt-caret">\u25B8</span></td>' +
                        '<td>' + esc(row.received) + '</td><td>' + esc(row.recipient) + '</td><td>' + statusBadge(row.status) + '</td><td>' +
                        (row.isExternal ? '<span class="badge badge-ext">External</span>' : '<span class="badge badge-int">Internal</span>') +
                        '</td><td>' + esc(row.fromIP) + '</td><td>' + esc(row.toIP) + '</td><td>' + esc(row.size) + '</td></tr>';
                    var detHtml = buildEventFlow(details);
                    body += '<tr class="mt-detail"><td colspan="8" style="padding:0;"><div class="mt-detail-content" id="' + detId + '">' + detHtml + '</div></td></tr>';
                }
                body += '</tbody></table></div>';
                html += '<div class="mv-body" id="mvbody-' + i + '">' + idSummary + body + '</div></div>';
            }
            host.innerHTML = html;
        }
        function toggleMvBody(id) {
            var b = el(id);
            if (b) { b.classList.toggle('show'); }
        }
        function toggleMtDetail(id, row) {
            var d = el(id);
            if (!d) { return; }
            d.classList.toggle('show');
            if (row) {
                var caret = row.querySelector('.mt-caret');
                if (caret) { caret.textContent = d.classList.contains('show') ? '\u25BE' : '\u25B8'; }
            }
        }
        function eventColor(ev) {
            var e = String(ev || '').toUpperCase();
            if (e.indexOf('FAIL') !== -1 || e.indexOf('DROP') !== -1 || e.indexOf('BOUNCE') !== -1 || e.indexOf('NDR') !== -1 || e.indexOf('REJECT') !== -1) { return '#e74c3c'; }
            if (e.indexOf('DELIVER') !== -1 || e.indexOf('SEND') !== -1) { return '#2ecc71'; }
            if (e.indexOf('RECEIVE') !== -1) { return '#3e97ff'; }
            if (e.indexOf('DEFER') !== -1 || e.indexOf('RETRY') !== -1 || e.indexOf('QUARANTINE') !== -1 || e.indexOf('SPAM') !== -1) { return '#f39c12'; }
            if (e.indexOf('SUBMIT') !== -1 || e.indexOf('RESOLVE') !== -1 || e.indexOf('EXPAND') !== -1 || e.indexOf('TRANSFER') !== -1) { return '#64748b'; }
            return '#7239ea';
        }
        function buildEventFlow(details) {
            if (!details || !details.length) {
                return '<div class="muted" style="padding:6px;">No delivery detail events available for this recipient.</div>';
            }
            var flow = '';
            for (var i = 0; i < details.length; i++) {
                var col = eventColor(details[i].event);
                var name = details[i].event || 'EVENT';
                flow += '<span class="ef-pill" style="color:' + col + ';background:' + col + '1f;">' + esc(name) + '</span>';
                if (i < details.length - 1) { flow += '<span class="ef-arrow">\u2192</span>'; }
            }
            var items = '';
            for (var j = 0; j < details.length; j++) {
                var c = eventColor(details[j].event);
                items += '<div class="ef-item">' +
                    '<span class="ef-dot" style="background:' + c + ';"></span>' +
                    '<div class="ef-event" style="color:' + c + ';">' + esc(details[j].event || 'Event') + '</div>' +
                    (details[j].detail ? '<div class="ef-detail">' + esc(details[j].detail) + '</div>' : '') +
                    (details[j].date ? '<div class="ef-date">' + esc(details[j].date) + '</div>' : '') +
                    '</div>';
            }
            return '<div class="ef-wrap">' +
                '<div class="ef-title"><span>\uD83D\uDCCC</span> Event Flow:</div>' +
                '<div class="ef-flow">' + flow + '</div>' +
                '<div class="ef-timeline">' + items + '</div></div>';
        }

        function renderRestrictedPanel() {
            var r = reportData.restricted || {};
            var body;
            if (r.isBlocked) {
                body = '<div class="kv"><strong>Blocked sender</strong> ' + esc(r.blockedSender) + '</div>' +
                    '<div class="kv"><strong>Blocked since</strong> ' + esc(r.timestamp) + '</div>' +
                    '<div class="kv"><strong>Reason</strong> ' + esc(r.reason) + '</div>' +
                    '<div class="kv"><strong>Entity (Account)</strong> ' + esc(r.identity) + '</div>' +
                    '<div class="guidance">To unblock and remove users from Restricted entities page follow the steps in <a href="https://learn.microsoft.com/defender-office-365/outbound-spam-restore-restricted-users" target="_blank" rel="noopener">the article</a>.</div>';
            } else if (r.lookupFailed) {
                body = '<div class="guidance">The restricted-entity lookup could not be completed, so restriction status is <strong>unknown</strong>. ' +
                    'Verify manually with <code>Get-BlockedSenderAddress -SenderAddress ' + esc(reportData.affectedUser) + '</code> in an Exchange Online-only session.' +
                    (r.error ? ('<br><br>Details: ' + esc(r.error)) : '') + '</div>';
            } else {
                body = '<div class="empty">This mailbox is not currently listed as a restricted entity.</div>';
            }
            el('panel-restricted').innerHTML = '<div class="section"><h2>Restricted Entity</h2>' + body + '</div>';
        }

        function renderAlertsPanel() {
            var a = reportData.alerts || {};
            var container = el('panel-alerts');
            if (a.skipped) {
                container.innerHTML = '<div class="section"><h2>Defender Alerts</h2><div class="empty">Defender / historical search was skipped for this run.</div></div>';
                return;
            }
            container.innerHTML = '<div class="section"><h2>Defender Alerts (last 30 days)</h2>' +
                '<div class="kv"><strong>Alert count</strong> ' + num(a.count) + '</div>' +
                '<div id="alertTableHost" style="margin-top:12px;"></div></div>';
            var cols = [
                { key: 'creationDate', label: 'Created' },
                { key: 'alertName', label: 'Alert' },
                { key: 'severity', label: 'Severity', render: function (r) { var s = String(r.severity || '').replace(/[^A-Za-z]/g, ''); return r.severity ? '<span class="badge badge-' + s + '">' + esc(r.severity) + '</span>' : ''; } },
                { key: 'category', label: 'Category' },
                { key: 'status', label: 'Status' },
                { key: '_details', label: 'View Details', sortable: false, render: function (r) { return '<button class="btn" type="button" onclick="showAlertDetails(\'' + encodeURIComponent(String(r.alertId || '')) + '\')">View details</button>'; } }
            ];
            makeTable(el('alertTableHost'), cols, a.list || [], { searchable: true, pageSize: 15 });
        }

        // Shared detail-modal renderer: builds a label/value table from a fields spec and opens the modal.
        function openDetailModal(title, fields, obj, extraHtml) {
            var rowsHtml = '';
            for (var f = 0; f < fields.length; f++) {
                var val = obj[fields[f][1]];
                if (val === null || val === undefined || val === '') { continue; }
                rowsHtml += '<tr><th style="text-align:left;vertical-align:top;white-space:nowrap;padding:6px 14px 6px 0;color:#2c3e50;">' +
                    esc(fields[f][0]) + '</th><td style="padding:6px 0;color:#475569;word-break:break-word;">' + esc(val) + '</td></tr>';
            }
            var body = '<table class="modal-detail-table" style="width:100%;border-collapse:collapse;font-size:13px;">' + rowsHtml + '</table>';
            if (extraHtml) { body += extraHtml; }
            el('alertModalTitle').textContent = title;
            el('alertModalBody').innerHTML = body;
            el('alertModal').style.display = 'flex';
        }

        function showAlertDetails(encId) {
            var id = decodeURIComponent(encId);
            var a = reportData.alerts || {};
            var list = a.list || [];
            var alert = null;
            for (var i = 0; i < list.length; i++) { if (String(list[i].alertId) === id) { alert = list[i]; break; } }
            if (!alert) { return; }
            // Ordered, human-friendly labels for every captured field.
            var fields = [
                ['Alert', 'alertName'], ['Alert ID', 'alertId'], ['Severity', 'severity'],
                ['Status', 'status'], ['Category', 'category'], ['Classification', 'classification'],
                ['Determination', 'determination'], ['Created', 'creationDate'],
                ['First activity', 'firstActivity'], ['Last activity', 'lastActivity'],
                ['Last update', 'lastUpdate'], ['Resolved', 'resolvedDateTime'],
                ['Detection source', 'detectionSource'], ['Service source', 'serviceSource'],
                ['Provider alert ID', 'providerAlertId'], ['Threat family', 'threatFamilyName'],
                ['Threat display name', 'threatDisplayName'], ['Actor', 'actorDisplayName'],
                ['Assigned to', 'assignedTo'], ['Incident ID', 'incidentId'],
                ['User', 'userDisplayName'], ['User principal name', 'userPrincipalName'],
                ['User account enabled', 'userAccountEnabled'], ['Device', 'deviceName'],
                ['IP address', 'ipAddress'], ['MITRE techniques', 'mitreTechniques'],
                ['Evidence count', 'evidenceCount'], ['Evidence summary', 'evidenceSummary'],
                ['Tenant ID', 'tenantId'], ['Description', 'description'],
                ['Recommended actions', 'recommendedActions'], ['Comments', 'comments']
            ];
            var links = '';
            if (alert.alertWebUrl) { links += '<a class="btn" href="' + esc(alert.alertWebUrl) + '" target="_blank" rel="noopener">Open alert in portal</a> '; }
            if (alert.incidentWebUrl) { links += '<a class="btn" href="' + esc(alert.incidentWebUrl) + '" target="_blank" rel="noopener">Open incident</a>'; }
            openDetailModal(alert.alertName || 'Alert details', fields, alert, links ? '<div style="margin-top:16px;">' + links + '</div>' : '');
        }

        function closeAlertDetails() { el('alertModal').style.display = 'none'; }

        function renderSendAsPanel() {
            var a = reportData.sendas || {};
            var container = el('panel-sendas');
            if (a.skipped) {
                container.innerHTML = '<div class="section"><h2>SendAs / SendOnBehalf Logs</h2><div class="empty">Unified audit log collection was skipped for this run.</div></div>';
                return;
            }
            if (a.error) {
                container.innerHTML = '<div class="section"><h2>SendAs / SendOnBehalf Logs</h2><div class="guidance">' + esc(a.error) + '</div></div>';
                return;
            }
            container.innerHTML = '<div class="section"><h2>SendAs / SendOnBehalf Logs (last ' + esc(reportData.lookbackDays) + ' days)</h2>' +
                '<div class="kv"><strong>Event count</strong> ' + num(a.count) + '</div>' +
                '<div id="sendAsTableHost" style="margin-top:12px;"></div></div>';
            var list = (a.list || []).map(function (x, i) { x._idx = i; return x; });
            var cols = [
                { key: 'creationTime', label: 'Created' },
                { key: 'operation', label: 'Operation' },
                { key: 'userId', label: 'Performed by' },
                { key: 'sendAsUserSmtp', label: 'SendAs SMTP' },
                { key: 'sendOnBehalfOfUserSmtp', label: 'SendOnBehalf SMTP' },
                { key: '_details', label: 'View Details', sortable: false, render: function (r) { return '<button class="btn" type="button" onclick="showSendAsDetails(' + r._idx + ')">View details</button>'; } }
            ];
            makeTable(el('sendAsTableHost'), cols, list, { searchable: true, pageSize: 15 });
        }

        function showSendAsDetails(idx) {
            var list = (reportData.sendas && reportData.sendas.list) || [];
            var e = list[idx];
            if (!e) { return; }
            var fields = [
                ['Created', 'creationTime'], ['Operation', 'operation'], ['Performed by (UserId)', 'userId'],
                ['SendAs SMTP', 'sendAsUserSmtp'], ['SendOnBehalf SMTP', 'sendOnBehalfOfUserSmtp'],
                ['Mailbox owner', 'mailboxOwnerUpn'], ['Client IP', 'clientIP'], ['Subject', 'subject'],
                ['Internet message ID', 'internetMessageId'],
                ['Result', 'resultStatus'], ['Workload', 'workload']
            ];
            openDetailModal((e.operation || 'SendAs') + ' event', fields, e);
        }

        // ---------- Mailbox Security Insights (donut + cards) ----------
        var securitySignalsList = [];
        var quarantineMessageList = [];
        var inboxRuleList = [];
        var delegationList = [];
        var freeWebmailList = [];
        function indicatorCard(ind, idx) {
            var met = ind.met;
            var color = met ? '#e74c3c' : '#27ae60';
            var badge = met ? 'YES' : 'NO';
            return '<div class="ind-card clickable" style="--indicator-color:' + color + ';" onclick="showIndicatorDetails(' + idx + ')">' +
                '<div class="ind-head"><span class="ind-name">' + esc(ind.name) + '</span>' +
                '<span class="ind-badge" style="background:' + color + ';">' + badge + '</span></div>' +
                '<div class="ind-progress"><div class="ind-bar" style="background:' + color + ';"></div></div>' +
                '<div class="ind-click">&#128269; Click to view details</div></div>';
        }
        function showIndicatorDetails(idx) {
            var ind = securitySignalsList[idx];
            if (!ind) { return; }
            var met = ind.met;
            var color = met ? '#e74c3c' : '#27ae60';
            var badgeText = met ? 'YES - ATTENTION NEEDED' : 'NO';
            var body = '<div style="background:' + color + '15;border:1px solid ' + color + ';border-left:4px solid ' + color + ';border-radius:8px;padding:16px;margin-bottom:18px;">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;">' +
                '<h3 style="margin:0;font-size:16px;color:#2c3e50;">Mailbox Security Insight Assessment</h3>' +
                '<span class="ind-badge" style="background:' + color + ';padding:6px 16px;">' + badgeText + '</span></div>' +
                '<div style="display:grid;grid-template-columns:1fr;gap:12px;">' +
                '<div style="background:#fff;border-radius:6px;padding:12px;box-shadow:0 2px 4px rgba(0,0,0,.1);"><div style="font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#64748b;margin-bottom:4px;">Attention Needed</div><div style="font-size:22px;font-weight:700;color:' + color + ';">' + (met ? 'Yes' : 'No') + '</div></div>' +
                '</div></div>' +
                '<div class="kv"><strong>Condition</strong> ' + esc(ind.condition) + '</div>' +
                '<div class="kv"><strong>Detail</strong> ' + esc(ind.detail) + '</div>';
            var messages = ind.messages || [];
            if (ind.detailType === 'quarantineMessages' && messages.length) {
                quarantineMessageList = messages;
                var messageRows = '';
                for (var i = 0; i < messages.length; i++) {
                    var message = messages[i];
                    messageRows += '<tr><td>' + esc(message.messageId || '') + '</td>' +
                        '<td><button class="btn" type="button" onclick="showQuarantineMessageDetails(' + i + ')">View details</button></td></tr>';
                }
                body += '<h3>Quarantined messages</h3><div class="table-scroll"><table><thead><tr>' +
                    '<th>MessageId</th><th>View Details</th>' +
                    '</tr></thead><tbody>' + messageRows + '</tbody></table></div>';
            }
            if (ind.detailType === 'inboxRules') {
                var rules = (reportData.health && reportData.health.securitySignalsRules) || [];
                if (rules.length) {
                    inboxRuleList = rules;
                    var ruleRows = '';
                    for (var ri = 0; ri < rules.length; ri++) {
                        ruleRows += '<tr><td>' + esc(rules[ri].name || '') + '</td>' +
                            '<td><button class="btn" type="button" onclick="showInboxRuleDetails(' + ri + ')">View details</button></td></tr>';
                    }
                    body += '<h3>Inbox rules</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Name</th><th>View Details</th>' +
                        '</tr></thead><tbody>' + ruleRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'externalForwarding') {
                var h = reportData.health || {};
                if (h.externalForward) {
                    var fwdRows = '<tr><td>' + esc(h.forwardingAddress || '') + '</td>' +
                        '<td><button class="btn" type="button" onclick="showExternalForwardingDetails()">View details</button></td></tr>';
                    body += '<h3>External forwarding</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>External forwarding</th><th>View Details</th>' +
                        '</tr></thead><tbody>' + fwdRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'delegation') {
                var delegs = (reportData.health && reportData.health.delegationEntries) || [];
                if (delegs.length) {
                    delegationList = delegs;
                    var delegRows = '';
                    for (var di = 0; di < delegs.length; di++) {
                        delegRows += '<tr><td>' + esc(delegs[di].user || '') + '</td>' +
                            '<td><button class="btn" type="button" onclick="showDelegationDetails(' + di + ')">View details</button></td></tr>';
                    }
                    body += '<h3>Delegation or SendAs permissions</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Delegation</th><th>View Details</th>' +
                        '</tr></thead><tbody>' + delegRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'defenderAlerts') {
                var alertsList = (reportData.alerts && reportData.alerts.list) || [];
                if (alertsList.length) {
                    var alertRows = '';
                    for (var ai = 0; ai < alertsList.length; ai++) {
                        alertRows += '<tr><td>' + esc(alertsList[ai].alertName || '') + '</td>' +
                            '<td><button class="btn" type="button" onclick="showAlertDetails(\'' + encodeURIComponent(String(alertsList[ai].alertId || '')) + '\')">View details</button></td></tr>';
                    }
                    body += '<h3>Active Defender alerts</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Alert name</th><th>View Details</th>' +
                        '</tr></thead><tbody>' + alertRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'freeWebmail') {
                var fwEntries = ind.entries || [];
                if (fwEntries.length) {
                    freeWebmailList = fwEntries;
                    var fwRows = '';
                    for (var fwi = 0; fwi < fwEntries.length; fwi++) {
                        fwRows += '<tr><td>' + esc(fwEntries[fwi].target || '') + '</td>' +
                            '<td><button class="btn" type="button" onclick="showFreeWebmailDetails(' + fwi + ')">View details</button></td></tr>';
                    }
                    body += '<h3>Auto-forward to free webmail</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Auto-forward</th><th>View Details</th>' +
                        '</tr></thead><tbody>' + fwRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'subjectSimilarity') {
                var subjEntries = ind.entries || [];
                if (subjEntries.length) {
                    subjectSimilarityList = subjEntries;
                    var subjRows = '';
                    for (var sui = 0; sui < subjEntries.length; sui++) {
                        subjRows += '<tr><td>' + esc(subjEntries[sui].subject || '') + '</td>' +
                            '<td>' + esc(subjEntries[sui].percentage) + '%</td>' +
                            '<td>' + esc(subjEntries[sui].messageCount) + '</td>' +
                            '<td>' + esc(subjEntries[sui].sentDateTime || '') + '</td></tr>';
                    }
                    body += '<h3>High similarity of message subjects</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Message subject</th><th>Percentage of messages</th><th>Message count</th><th>Message sent date and time</th>' +
                        '</tr></thead><tbody>' + subjRows + '</tbody></table></div>';
                }
            }
            if (ind.detailType === 'auditEnabled') {
                var auditEntries = ind.entries || [];
                if (auditEntries.length) {
                    var auditRows = '';
                    for (var adi = 0; adi < auditEntries.length; adi++) {
                        auditRows += '<tr><td>' + esc(auditEntries[adi].name || '') + '</td>' +
                            '<td>' + esc(auditEntries[adi].value || '') + '</td></tr>';
                    }
                    body += '<h3>Mailbox audit properties</h3><div class="table-scroll"><table><thead><tr>' +
                        '<th>Property</th><th>Value</th>' +
                        '</tr></thead><tbody>' + auditRows + '</tbody></table></div>';
                }
            }
            el('alertModalTitle').textContent = ind.name;
            el('alertModalBody').innerHTML = body;
            el('alertModal').style.display = 'flex';
        }
        function showFreeWebmailDetails(idx) {
            var e = freeWebmailList[idx];
            if (!e) { return; }
            var fields = [
                ['Auto-forward target', 'target'], ['Source', 'source'], ['Matched webmail domain', 'matchedDomain']
            ];
            openDetailModal('Auto-forward to free webmail details', fields, e);
        }
        function showDelegationDetails(idx) {
            var d = delegationList[idx];
            if (!d) { return; }
            var fields = [
                ['Permission type', 'permissionType'], ['User', 'user'], ['Access rights', 'accessRights'],
                ['Access control type', 'accessControlType'], ['Deny', 'deny'], ['Inheritance type', 'inheritanceType']
            ];
            openDetailModal('Delegation / SendAs details', fields, d);
        }
        function showExternalForwardingDetails() {
            var h = reportData.health || {};
            var fields = [
                ['Forwarding address', 'forwardingAddress'], ['Deliver and forward', 'deliverAndForward']
            ];
            openDetailModal('External forwarding details', fields, h);
        }
        function showInboxRuleDetails(idx) {
            var rule = inboxRuleList[idx];
            if (!rule) { return; }
            var fields = [
                ['Name', 'name'], ['Enabled', 'enabled'], ['Forward to', 'forwardTo'],
                ['Redirect to', 'redirectTo'], ['Delete message', 'deleteMessage'], ['Description', 'description'],
                ['Priority', 'priority'], ['MailboxOwnerId', 'mailboxOwnerId']
            ];
            openDetailModal('Inbox rule details', fields, rule);
        }
        function showQuarantineMessageDetails(idx) {
            var m = quarantineMessageList[idx];
            if (!m) { return; }
            var fields = [
                ['MessageId', 'messageId'], ['SenderAddress', 'senderAddress'], ['RecipientAddress', 'recipientAddress'],
                ['Subject', 'subject'], ['Type', 'type'], ['EntityType', 'entityType'],
                ['PolicyType', 'policyType'], ['PolicyName', 'policyName'], ['QuarantineTypes', 'quarantineTypes'],
                ['ReleaseStatus', 'releaseStatus'], ['ReceivedTime', 'receivedTime'], ['SystemReleased', 'systemReleased'],
                ['Expires', 'expires'], ['Reported', 'reported']
            ];
            openDetailModal('Quarantined message details', fields, m);
        }
        function renderIndicatorDonut(total, attentionNeeded) {
            var pct = total > 0 ? Math.round(attentionNeeded / total * 100) : 0;
            var circ = 339.29;
            var offset = circ * (1 - pct / 100);
            var color = attentionNeeded > 0 ? '#e74c3c' : '#27ae60';
            return '<svg width="130" height="130" viewBox="0 0 130 130">' +
                '<circle cx="65" cy="65" r="54" fill="none" stroke="#eef0f4" stroke-width="12"></circle>' +
                '<circle cx="65" cy="65" r="54" fill="none" stroke="' + color + '" stroke-width="12" stroke-linecap="round" stroke-dasharray="' + circ + '" stroke-dashoffset="' + offset + '" transform="rotate(-90 65 65)"></circle>' +
                '<text x="65" y="62" text-anchor="middle" font-size="26" font-weight="700" fill="#2c3e50">' + pct + '%</text>' +
                '<text x="65" y="82" text-anchor="middle" font-size="10" fill="#64748b">attention needed</text></svg>';
        }
        function renderSecuritySignals() {
            var v = reportData.verdict || {};
            var indicators = v.securitySignals || [];
            var attentionNeeded = num(v.attentionNeededCount);
            var noAttention = num(v.noAttentionCount);
            var total = attentionNeeded + noAttention;
            var sorted = indicators.slice().sort(function (a, b) { return (b.met ? 1 : 0) - (a.met ? 1 : 0); });
            securitySignalsList = sorted;
            var cards = '';
            for (var ci = 0; ci < sorted.length; ci++) { cards += indicatorCard(sorted[ci], ci); }
            var indGrid = indicators.length ? '<div class="ind-grid">' + cards + '</div>' : '<div class="empty">No insights evaluated.</div>';
            var overview = '<div class="si-overview">' + renderIndicatorDonut(total, attentionNeeded) +
                '<div class="si-overview-text"><div class="si-title">Mailbox Security Insights</div>' +
                '<div class="si-sub">' + noAttention + ' of ' + total + ' insights need no attention</div>' +
                '<div class="si-badges"><span class="count-badge passed">No Attention: ' + noAttention + '</span>' +
                '<span class="count-badge failed">Attention Needed: ' + attentionNeeded + '</span>' +
                '<span class="count-badge total">Total: ' + total + '</span></div></div></div>';
            return '<div class="section"><h2>Mailbox Security Insights</h2>' + overview + indGrid + '</div>';
        }

        // ---------- Verdict summary ----------
        function buildVerdictSummary() {
            var v = reportData.verdict || {}, t = reportData.trace || {}, p = reportData.policy || {}, r = reportData.restricted || {};
            var lines = [];
            lines.push('SENDER RESTRICTION ANALYZER VERDICT SUMMARY');
            lines.push('Affected user: ' + reportData.affectedUser + ' (' + reportData.displayName + ')');
            lines.push('Generated: ' + reportData.reportTimestamp);
            lines.push('Verdict: ' + v.classification + (v.blockType ? ' (' + v.blockType + ')' : ''));
            lines.push('Restriction: ' + (r.isBlocked ? ('Blocked since ' + r.timestamp + ' \u2014 ' + r.reason) : 'Not restricted'));
            lines.push('Policy: ' + p.name + ' | daily=' + p.dailyLimit + ' extHourly=' + p.externalHourlyLimit + ' intHourly=' + p.internalHourlyLimit + ' action=' + p.action);
            lines.push('Volume: peakDaily=' + t.maxDaily + ' effectiveLimit=' + t.effectiveLimit + ' totalMsgs=' + t.totalMessages + ' uniqueExternal=' + t.uniqueExternal + ' peak60min=' + t.peakRolling60);
            return lines.join('\n');
        }

        // ---------- Init ----------
        function init() {
            renderHeader();
            renderKpis();
            renderTabs();
            renderVerdictPanel();
            renderTracePanel();
            renderRestrictedPanel();
            renderPolicyPanel();
            renderAlertsPanel();
            renderSendAsPanel();
            el('panel-indicators').innerHTML = renderSecuritySignals();
            el('panel-recommendations').innerHTML = renderRecommendations();
            el('copyVerdictSummary').addEventListener('click', function () { copyText(buildVerdictSummary()); });
            document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeAlertDetails(); } });
            document.title = 'Sender Restriction Analysis - ' + reportData.affectedUser;
        }
        if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
    </script>
    <div id="alertModal" class="modal-overlay" onclick="if(event.target===this)closeAlertDetails()">
        <div class="modal-box" role="dialog" aria-modal="true">
            <div class="modal-head">
                <h3 id="alertModalTitle">Alert details</h3>
                <button type="button" class="modal-close" onclick="closeAlertDetails()" aria-label="Close">&times;</button>
            </div>
            <div id="alertModalBody" class="modal-body"></div>
        </div>
    </div>
</body>
</html>
"@

    return $html
}
#endregion

#endregion

#region Phase persistence (Phase 1 export / Phase 2 import)
#region Export-RrlEvidence
function Export-RrlEvidence {
    <#
    .SYNOPSIS
        PHASE 1 writer. Persists the collected evidence to per-dataset CSV files (human-openable)
        AND a single CLIXML state file that preserves the full object graph (nested trace-detail
        timelines, datetimes, aggregations) so PHASE 2 can rebuild the report fully offline.
        Returns the state-file path (or $null if it could not be written).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$RrlData,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$Upn,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )

    $upnSafe = ($Upn -replace '[^A-Za-z0-9]+', '_')
    $prefix = Join-Path -Path $OutputPath -ChildPath "RRL_${upnSafe}_${Timestamp}"

    $writeCsv = {
        param($Name, $Rows)
        $arr = @($Rows)
        if ($arr.Count -eq 0) { Write-Verbose "No rows for $Name; skipping CSV."; return }
        $path = "${prefix}_$Name.csv"
        try { $arr | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -Force; Write-Verbose "Exported $Name -> $path" }
        catch { Write-Warning "Failed to export $Name CSV: $_" }
    }

    # 1) Message trace rows (nested delivery events serialized into a JSON column for the CSV view)
    if ($RrlData.MessageTrace -and $RrlData.MessageTrace.Success -and $RrlData.MessageTrace.RawMessages) {
        $mtRows = @($RrlData.MessageTrace.RawMessages | ForEach-Object {
            $td = @()
            if ($_.PSObject.Properties['TraceDetails'] -and $_.TraceDetails) { $td = @($_.TraceDetails) }
            [PSCustomObject]@{
                Received         = if ($_.Received) { ([datetime]$_.Received).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                SenderAddress    = [string]$_.SenderAddress
                RecipientAddress = [string]$_.RecipientAddress
                Subject          = [string]$_.Subject
                Status           = [string]$_.Status
                MessageId        = [string]$_.MessageId
                MessageTraceId   = [string]$_.MessageTraceId
                FromIP           = [string]$_.FromIP
                ToIP             = [string]$_.ToIP
                Size             = [string]$_.Size
                IsExternal       = [bool]$_.IsExternal
                TraceDetailsJson = if ($td.Count -gt 0) { ($td | ConvertTo-Json -Compress -Depth 5) } else { '' }
            }
        })
        & $writeCsv 'MessageTrace' $mtRows
    }

    # 2) Message-trace aggregations
    if ($RrlData.MessageTrace -and $RrlData.MessageTrace.Success) {
        & $writeCsv 'DailyStats' $RrlData.MessageTrace.DailyStats
        & $writeCsv 'StatusBreakdown' $RrlData.MessageTrace.StatusBreakdown
        & $writeCsv 'TopRecipientDomains' $RrlData.MessageTrace.TopRecipientDomains
    }

    # 3) Restricted-entity status
    if ($RrlData.RestrictedEntity) {
        & $writeCsv 'RestrictedEntity' @([PSCustomObject]@{
            Success              = $RrlData.RestrictedEntity.Success
            IsBlocked            = $RrlData.RestrictedEntity.IsBlocked
            BlockedSenderAddress = $RrlData.RestrictedEntity.BlockedSenderAddress
            LastBlockedDateTime  = $RrlData.RestrictedEntity.LastBlockedDateTime
            Reason               = $RrlData.RestrictedEntity.Reason
            Error                = $RrlData.RestrictedEntity.Error
        })
    }

    # 4) SendAs / SendOnBehalf events
    if ($RrlData.SendAsLogs -and $RrlData.SendAsLogs.Entries) { & $writeCsv 'SendAsLogs' $RrlData.SendAsLogs.Entries }

    # 5) Defender alerts
    if ($RrlData.DefenderAlerts -and $RrlData.DefenderAlerts.Alerts) { & $writeCsv 'DefenderAlerts' $RrlData.DefenderAlerts.Alerts }

    # 6) Inbox rules
    if ($RrlData.AccountHealth -and $RrlData.AccountHealth.SecuritySignalsRules) { & $writeCsv 'SuspiciousInboxRules' $RrlData.AccountHealth.SecuritySignalsRules }

    # Full-fidelity state file for offline Phase 2 (depth high enough for RawMessages -> TraceDetails).
    $statePath = "${prefix}_State.clixml"
    try {
        $RrlData | Export-Clixml -Path $statePath -Depth 12
        Write-Verbose "Exported state -> $statePath"
    }
    catch {
        Write-Warning "Failed to export state file: $_"
        $statePath = $null
    }
    return $statePath
}
#endregion

#region Import-RrlState
function Import-RrlState {
    <#
    .SYNOPSIS
        PHASE 2 reader. Re-hydrates the CLIXML state file written by Export-RrlEvidence into a
        real hashtable suitable for the offline verdict engine and HTML report builder.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$StatePath)

    $imported = Import-Clixml -Path $StatePath
    $ht = @{}
    foreach ($k in $imported.Keys) { $ht[$k] = $imported[$k] }
    return $ht
}
#endregion
#endregion

#region Main Script Logic
try {
    # Resolve output path (PSScriptRoot can be empty when dot-sourced in some hosts)
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
    }

    # Display header
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "      Sender Restriction Analyzer       " -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Interactive prompts if parameters not provided
    while (-not $AffectedUPN -or $AffectedUPN -notmatch '^[^@]+@[^@]+\.[^@]+$') {
        Write-Host "=== RRL Analysis: Affected User ===" -ForegroundColor Yellow
        $AffectedUPN = Read-Host "Enter the affected user's UPN (e.g., user@contoso.com)"
        if ($AffectedUPN -notmatch '^[^@]+@[^@]+\.[^@]+$') {
            Write-Warning "Invalid UPN format. Please enter a valid email address."
            $AffectedUPN = $null
        }
    }
    
    if (-not $AdminUPN) {
        Write-Host "`n=== Connection Account ===" -ForegroundColor Yellow
        $AdminUPN = Read-Host "Enter admin UPN for connection (or press Enter to use current context)"
    }
    
    # Configuration summary and confirmation
    Write-Host "`n=== RRL Analysis Configuration ===" -ForegroundColor Cyan
    Write-Host "  Affected User : $AffectedUPN"
    Write-Host "  Admin Account : $(if ($AdminUPN) { $AdminUPN } else { '(current context)' })"
    Write-Host "  Lookback Days : $LookbackDays"
    Write-Host "  Skip Defender : $($SkipDefender.IsPresent)"
    Write-Host "  Output Path   : $OutputPath"
    Write-Host ""

    # Module prerequisite checks
    Write-Verbose "Checking module prerequisites..."
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Select-Object -First 1
    if (-not $exoModule) {
        Write-Error "ExchangeOnlineManagement module is required but not installed. Install: Install-Module ExchangeOnlineManagement"
        exit 1
    }
    Write-Verbose "ExchangeOnlineManagement module found: v$($exoModule.Version)"
    
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Select-Object -First 1
    if (-not $graphModule) {
        Write-Warning "Microsoft.Graph.Authentication module not found. Defender alert signals will be unavailable. Install: Install-Module Microsoft.Graph.Authentication"
    }
    else {
        Write-Verbose "Microsoft.Graph.Authentication module found: v$($graphModule.Version)"
    }
    
    # Connect to services
    $connectGraph = $null -ne $graphModule
    $connected = Connect-RrlServices -AdminUpn $AdminUPN -SkipDefender:$SkipDefender -ConnectGraph:$connectGraph
    if (-not $connected) {
        Write-Error "Failed to connect to required services. Exiting."
        exit 1
    }
    
    Write-Host "`n[INFO] Starting data collection..." -ForegroundColor Green
    
    # Initialize data collection hashtable
    $script:RrlData = @{
        Recipient = $null
        Policy = $null
        MessageTrace = $null
        RestrictedEntity = $null
        SendAsLogs = $null
        DefenderAlerts = $null
        AccountHealth = $null
        SecuritySignals = $null
        AnalysisTimestamp = Get-Date
        LookbackDays = $LookbackDays
        SkipDefender = $SkipDefender.IsPresent
    }
    
    # Step 1: Validate recipient
    $recipientResult = Get-RrlRecipientValidation -Upn $AffectedUPN
    $script:RrlData.Recipient = $recipientResult
    
    if (-not $recipientResult.Success -or -not $recipientResult.Exists) {
        Write-Error "Recipient validation failed: $($recipientResult.Error)"
        exit 1
    }
    
    Write-Information -MessageData "[INFO] ✓ $($recipientResult.DisplayName) ($($recipientResult.RecipientTypeDetails))" -InformationAction Continue

    # Phase 2: launch the Microsoft Graph "lane" (Defender alerts) concurrently with the
    # Exchange Online data collection below. Only pure-Graph work is offloaded because EXO
    # cmdlets are not thread-safe across runspaces. $graphLane is $null when concurrency is
    # unavailable or disabled, in which case Step 6 computes the alerts inline.
    $graphLane = $null
    if (-not $SkipDefender -and -not $SkipHistoricalSearch) {
        $graphLane = Start-RrlGraphLane -Upn $AffectedUPN -DisplayName $recipientResult.DisplayName -SkipDefender:$SkipDefender -SkipHistoricalSearch:$SkipHistoricalSearch
        if ($graphLane) {
            Write-Verbose "[TIMING] Defender-alert lane started ($($graphLane.Kind)); running concurrently with EXO steps."
        }
    }
    
    # Step 2: Get outbound spam policy
    $policyResult = Measure-RrlStep -Name 'Step2-OutboundSpamPolicy' -Script { Get-RrlOutboundSpamPolicy -Upn $AffectedUPN }
    $script:RrlData.Policy = $policyResult
    
    if ($policyResult.Success) {
        Write-Verbose "Policy: $($policyResult.PolicyName)"
    }
    else {
        Write-Warning "Policy retrieval failed: $($policyResult.Error)"
    }
    
    # Step 3: Get message trace
    $traceResult = Measure-RrlStep -Name 'Step3-MessageTrace' -Script { Get-RrlMessageTrace -Upn $AffectedUPN -LookbackDays $LookbackDays -SkipMessageTraceDetail:$SkipMessageTraceDetail -MaxDetailLookups $MaxDetailLookups -ParallelDetailLookups:$ParallelDetailLookups -DetailThrottleLimit $DetailThrottleLimit -AdminUpn $AdminUPN }
    $script:RrlData.MessageTrace = $traceResult
    
    if ($traceResult.Success) {
        Write-Information -MessageData "[INFO] ✓ Retrieved $($traceResult.TotalMessages) messages ($($traceResult.TotalRecipients) recipients)" -InformationAction Continue
    }
    else {
        Write-Warning "Message trace retrieval failed: $($traceResult.Error)"
    }
    
    # Step 5: Check restricted entities
    $restrictedResult = Measure-RrlStep -Name 'Step5-RestrictedEntity' -Script { Get-RrlRestrictedEntity -Upn $AffectedUPN -SkipDefender:$SkipDefender }
    $script:RrlData.RestrictedEntity = $restrictedResult
    
    if ($restrictedResult.Success -and $restrictedResult.IsBlocked) {
        Write-Information -MessageData "[INFO] ⚠ User is restricted: $($restrictedResult.Reason)" -InformationAction Continue
    }
    elseif ($restrictedResult.Success -and -not $restrictedResult.IsBlocked) {
        Write-Information -MessageData "[INFO] ✓ User is not restricted" -InformationAction Continue
    }
    
    # Step 5.5: Collect SendAs / SendOnBehalf unified audit logs
    $sendAsResult = Measure-RrlStep -Name 'Step5.5-SendAsLogs' -Script { Get-RrlSendAsLogs -Upn $AffectedUPN -LookbackDays $LookbackDays -SkipDefender:$SkipDefender }
    $script:RrlData.SendAsLogs = $sendAsResult
    if ($sendAsResult.Success -and $sendAsResult.Found) {
        Write-Information -MessageData "[INFO] ✓ Found $($sendAsResult.Count) SendAs/SendOnBehalf event(s)" -InformationAction Continue
    }
    
    # Step 6: Get Defender alerts. If the concurrent Graph lane was started, collect its
    # result here (it has been running while EXO steps executed). Otherwise compute inline.
    $alertsResult = Measure-RrlStep -Name 'Step6-DefenderAlerts' -Script {
        if ($graphLane) {
            $laneResult = Receive-RrlGraphLane -Lane $graphLane
            if ($null -ne $laneResult) {
                Write-Verbose "[TIMING] Defender-alert lane result collected."
                return $laneResult
            }
            Write-Verbose "Defender-alert lane returned no result; falling back to inline retrieval."
        }
        Get-RrlDefenderAlerts -Upn $AffectedUPN -DisplayName $recipientResult.DisplayName -SkipDefender:$SkipDefender -SkipHistoricalSearch:$SkipHistoricalSearch
    }
    $script:RrlData.DefenderAlerts = $alertsResult
    
    if ($alertsResult.Success -and $alertsResult.AlertsFound) {
        Write-Information -MessageData "[INFO] ⚠ Found $($alertsResult.AlertCount) Defender alerts" -InformationAction Continue
    }
    
    # Step 7: Check account health
    $healthResult = Measure-RrlStep -Name 'Step7-AccountHealth' -Script { Get-RrlAccountHealth -Upn $AffectedUPN -Mailbox $recipientResult.MailboxObject }
    $script:RrlData.AccountHealth = $healthResult
    
    if ($healthResult.Success) {
        if ($healthResult.HasExternalForward -or $healthResult.SecuritySignalsRulesCount -gt 0) {
            Write-Warning "⚠ Mailbox security insights need attention"
        }
        else {
            Write-Verbose "Account health: No mailbox security insights need attention"
        }
    }
    
    # Step 7.5: Collect supplemental identity and threat signals (expanded indicators)
    $securityResult = Measure-RrlStep -Name 'Step7.5-SecuritySignals' -Script { Get-RrlSecuritySignals -Upn $AffectedUPN -SkipDefender:$SkipDefender }
    $script:RrlData.SecuritySignals = $securityResult
    
    Write-Information -MessageData "[INFO] ✓ Data collection complete" -InformationAction Continue

    # Phase 2: emit a timing summary of the data-collection steps (visible with -Verbose).
    if ($script:RrlTimings -and $script:RrlTimings.Count -gt 0) {
        $timingTotal = ($script:RrlTimings.Values | Measure-Object -Sum).Sum
        Write-Verbose "[TIMING] ---- Data collection step summary ----"
        foreach ($tk in $script:RrlTimings.Keys) {
            Write-Verbose ("[TIMING]   {0}: {1:N2}s" -f $tk, $script:RrlTimings[$tk])
        }
        Write-Verbose ("[TIMING]   Sum of measured steps: {0:N2}s" -f $timingTotal)
    }
    
    # ===== PHASE 1: EXPORT LOGS (per-dataset CSVs + full-fidelity state file) =====
    Write-Host "`n========== PHASE 1: EXPORT LOGS ==========" -ForegroundColor Cyan
    $localPart = $AffectedUPN.Split('@')[0]
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $statePath = Export-RrlEvidence -RrlData $script:RrlData -OutputPath $OutputPath -Upn $AffectedUPN -Timestamp $timestamp
    Write-Information -MessageData "[INFO] ✓ Evidence exported (per-dataset CSVs + state file) to $OutputPath" -InformationAction Continue

    # Disconnect all cloud services — Phase 2 is fully offline (reads the exported state file only).
    Write-Host "`nDisconnecting from cloud services (Phase 2 runs offline)..." -ForegroundColor Cyan
    Disconnect-RrlServices
    Write-Host "All cloud connections closed. Proceeding with offline analysis..." -ForegroundColor Green

    # ===== PHASE 2: GENERATE HTML REPORT (OFFLINE) =====
    Write-Host "`n========== PHASE 2: GENERATE HTML REPORT (OFFLINE) ==========" -ForegroundColor Cyan
    if ($statePath -and (Test-Path -Path $statePath)) {
        Write-Information -MessageData "[INFO] Reading exported state: $statePath" -InformationAction Continue
        $offlineData = Import-RrlState -StatePath $statePath
    }
    else {
        Write-Warning "State file unavailable; falling back to in-memory data for report generation."
        $offlineData = $script:RrlData
    }

    # Verdict engine (offline computation over the exported evidence — no remote calls)
    $verdict = Invoke-RrlVerdictAnalysis -RrlData $offlineData -Thresholds $script:RrlThresholds
    $offlineData.Verdict = $verdict

    Write-Information -MessageData "[INFO] Verdict: $($verdict.Classification)" -InformationAction Continue

    # Generate HTML report (offline)
    Write-Information -MessageData "[INFO] Generating HTML report..." -InformationAction Continue

    # Display confidential data warning
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  CONFIDENTIAL OUTPUT WARNING" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "The report contains sensitive data including:" -ForegroundColor Yellow
    Write-Host "  - User Principal Names and recipient addresses" -ForegroundColor Yellow
    Write-Host "  - Message subjects and Message IDs" -ForegroundColor Yellow
    Write-Host "  - Security posture and mailbox security insights" -ForegroundColor Yellow
    Write-Host "Treat as CONFIDENTIAL. Do not email unencrypted.`n" -ForegroundColor Yellow

    $reportFilename = "RRLAnalysis_${localPart}_${timestamp}.html"
    $reportPath = Join-Path -Path $OutputPath -ChildPath $reportFilename

    # Generate HTML content from the offline (exported) data
    $htmlContent = Get-RrlHtmlReport -RrlData $offlineData -UserPrincipalName $AffectedUPN

    # Write report
    $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8 -Force

    Write-Host "[INFO] Report written to:" -ForegroundColor Green
    Write-Host "  $reportPath" -ForegroundColor White
    
    # Prompt to open
    $openPrompt = Read-Host "`nOpen report now? (Y/N)"
    if ($openPrompt -eq 'Y' -or $openPrompt -eq 'y') {
        Start-Process $reportPath
    }
    
    Write-Host "`n[INFO] RRL Analysis complete." -ForegroundColor Green
    
}
catch {
    Write-Error "Fatal error during RRL analysis: $_"
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    # Guaranteed cleanup
    Disconnect-RrlServices
    Write-ProgressHelper -Completed
}
#endregion
