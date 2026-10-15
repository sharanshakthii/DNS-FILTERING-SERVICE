<#
  start.ps1 -- PRJ_112 permanent startup launcher.

  Run this file directly, from ANY working directory:

      & "E:\prj112 (26)\prj112\start.ps1"

  It locates the project from its own file location ($PSScriptRoot), so it
  does not matter whether PowerShell started in "E:\prj112 (26)" or
  elsewhere -- you never need to `cd` into the project first.

  It changes nothing in the application itself: it only sets the same
  environment variables you were already exporting by hand, then starts the
  DNS proxy and the API exactly as documented (proxy/dns_proxy.py,
  api/main.py), each in its own window so you can see both logs live.

  -- Secrets are deliberately NOT set here -----------------------------
  DNSF_FEED_AUTH_KEY (URLhaus), DNSF_AUTH_USERNAME and
  DNSF_AUTH_PASSWORD_HASH are credentials and must not live in a file that
  sits in the project folder. Set them ONCE, permanently, as Windows user
  environment variables and every future run of this script (and every new
  terminal) will already have them -- nothing to re-type, nothing in source
  control.

  One-time setup, run yourself in a terminal (values never shown to anyone
  else, nothing written to any file):

      setx DNSF_FEED_AUTH_KEY "<your URLhaus Auth-Key>"
      setx DNSF_AUTH_USERNAME "<your username>"
      setx DNSF_AUTH_PASSWORD_HASH "<your pbkdf2_sha256$... hash from tools\make_password_hash.py>"

  Close and reopen PowerShell once after running `setx` -- it only affects
  new processes, not the terminal you ran it in.

  -- Two modes ----------------------------------------------------------
      & "E:\prj112 (26)\prj112\start.ps1"              # live (default)
      & "E:\prj112 (26)\prj112\start.ps1" -Mode paper  # reproduces the paper

  live   Five live no-auth threat-intelligence feeds, refreshed hourly; a
         feed listing is decisive (score 1.0); registration age via RDAP.
         For demonstrations and real use.
  paper  The configuration the IEEE paper's results were produced with:
         the pinned data/urlhaus.csv snapshot, the plain weighted mean of
         formula (2), and the five original modules. Use this to reproduce
         or show anything the paper reports.
#>

param(
    [ValidateSet("live", "paper")]
    [string]$Mode = "live"
)

$ErrorActionPreference = "Stop"

# -- locate the project regardless of the caller's current directory -------
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

$venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "No virtual environment at $venvPython. Create it first: python -m venv .venv"
}

# -- known-good detection configuration (not secret, safe to keep here) ----
$env:DNSF_AGGREGATOR_ENFORCE = "true"
$env:DNSF_TYPOSQUAT_BRANDS   = "google,paypal,microsoft,apple,amazon,facebook,instagram,netflix,linkedin,github"

# -- TI feed source and aggregation, pinned explicitly per mode ------------
# Every variable that decides the feed is set here, never inherited, so an
# old terminal's DNSF_FEED_FILE cannot silently switch which database a
# verdict came from. Same domain, two databases, two verdicts, no warning --
# that is the failure this block exists to prevent.
if ($Mode -eq "paper") {
    $snapshot = Join-Path $ProjectRoot "data\urlhaus.csv"
    if (-not (Test-Path $snapshot)) {
        throw "Paper mode needs the pinned snapshot at $snapshot"
    }
    $env:DNSF_ENGINE_MODULES        = "ti,nrd,typosquat,dga,beaconing"
    $env:DNSF_FEED_NAME             = "urlhaus"
    $env:DNSF_FEED_FILE             = $snapshot
    $env:DNSF_FEED_FORMAT           = "csv"
    $env:DNSF_FEED_URL              = ""
    $env:DNSF_FEED_AUTH_KEY         = ""      # local file; no key involved
    $env:DNSF_AGGREGATOR_TI_DECISIVE = "false" # formula (2) exactly
    $env:DNSF_PSL_MODE              = "off"   # last-two-labels, as published
    $env:DNSF_DGA_MODEL_PATH        = "models/dga/dga_model.json"     # v1, as published
} else {
    $env:DNSF_ENGINE_MODULES        = "ti,nrd,typosquat,dga,beaconing,rdap"
    $env:DNSF_FEED_NAME             = "phishing-domains"
    $env:DNSF_FEED_FILE             = ""
    $env:DNSF_FEED_FORMAT           = "domains"
    $env:DNSF_FEED_URL              = ""
    $env:DNSF_AGGREGATOR_TI_DECISIVE = "true"
    $env:DNSF_PSL_MODE              = "full"  # Public Suffix List, incl. platforms
    $env:DNSF_DGA_MODEL_PATH        = "models/dga/dga_model_v2.json"  # no label_count
    $env:DNSF_FEED_EXTRA_DEFAULTS   = "true"
    # A URLhaus key without its per-account export URL makes the feed layer
    # refuse to start (feeds/sources.py build_urlhaus_source). Live mode uses
    # the no-auth feeds, so a key set globally is set aside for this launch
    # rather than allowed to take threat intelligence down.
    if ($env:DNSF_FEED_AUTH_KEY) {
        Write-Warning "DNSF_FEED_AUTH_KEY is set but live mode uses the no-auth feeds; ignoring it for this launch."
        $env:DNSF_FEED_AUTH_KEY = ""
    }
}

# -- secrets must already be set as persistent user environment variables --
$requiredSecrets = "DNSF_AUTH_USERNAME", "DNSF_AUTH_PASSWORD_HASH"
$missing = $requiredSecrets | Where-Object { -not (Test-Path "env:$_") }
if ($missing) {
    Write-Warning "Not set in this environment: $($missing -join ', ')"
    Write-Warning "See the comment at the top of start.ps1 for the one-time 'setx' commands."
    Write-Warning "Continuing anyway - the feed and/or authentication will run in their degraded/open mode, same as the underlying project already does when these are unset."
}

Write-Host "PRJ_112 -- starting from $ProjectRoot" -ForegroundColor Cyan
Write-Host "  mode:       $Mode"
Write-Host "  modules:    $($env:DNSF_ENGINE_MODULES)"
Write-Host "  enforce:    $($env:DNSF_AGGREGATOR_ENFORCE)"
Write-Host "  brands:     $($env:DNSF_TYPOSQUAT_BRANDS)"

# -- Terminal 1: DNS proxy (127.0.0.1:5353) --------------------------------
Start-Process powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @(
    "-NoExit", "-Command",
    "Write-Host 'PRJ_112 - DNS proxy' -ForegroundColor Cyan; & '$venvPython' -m proxy.dns_proxy"
)

Start-Sleep -Seconds 2

# -- Terminal 2: FastAPI + dashboard (127.0.0.1:8000) ----------------------
Start-Process powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @(
    "-NoExit", "-Command",
    "Write-Host 'PRJ_112 - API + dashboard' -ForegroundColor Cyan; & '$venvPython' -m uvicorn api.main:app --port 8000"
)

Write-Host ""
Write-Host "Two windows opened: DNS proxy (5353) and API (8000)." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:8000/dashboard/" -ForegroundColor Green
