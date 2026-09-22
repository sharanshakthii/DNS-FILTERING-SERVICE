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
#>

$ErrorActionPreference = "Stop"

# -- locate the project regardless of the caller's current directory -------
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

$venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "No virtual environment at $venvPython. Create it first: python -m venv .venv"
}

# -- known-good detection configuration (not secret, safe to keep here) ----
$env:DNSF_ENGINE_MODULES     = "ti,nrd,typosquat,dga,beaconing"
$env:DNSF_AGGREGATOR_ENFORCE = "true"
$env:DNSF_TYPOSQUAT_BRANDS   = "google,paypal,microsoft,apple,amazon,facebook,instagram,netflix,linkedin,github"

# -- secrets must already be set as persistent user environment variables --
$requiredSecrets = "DNSF_FEED_AUTH_KEY", "DNSF_AUTH_USERNAME", "DNSF_AUTH_PASSWORD_HASH"
$missing = $requiredSecrets | Where-Object { -not (Test-Path "env:$_") }
if ($missing) {
    Write-Warning "Not set in this environment: $($missing -join ', ')"
    Write-Warning "See the comment at the top of start.ps1 for the one-time 'setx' commands."
    Write-Warning "Continuing anyway - the feed and/or authentication will run in their degraded/open mode, same as the underlying project already does when these are unset."
}

Write-Host "PRJ_112 -- starting from $ProjectRoot" -ForegroundColor Cyan
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
