#Requires -Version 5.1
<#
.SYNOPSIS
    Assemble the ADscan Windows LITE bundle reproducibly, and optionally wrap it
    into a onefile adscan.exe with PyInstaller.

.DESCRIPTION
    Captures the hand-verified Windows bundle that compromised a domain on a
    Windows Server 2016 test host. The bundle shape (relative to -OutDir):

        py\        embeddable CPython 3.12 (python.exe + python312.zip + dlls),
                   with py\python312._pth edited to expose the app + deps + the
                   vendored native stack.
        site\      all third-party pip deps unpacked (Windows wheels).
        vendor\    the committed skelsec stack (aardwolf/aiosmb/asysocks/
                   badauth/badldap/kerbad/pypykatz/winacl).
        adscan.py + adscan_internal\ + adscan_core\   the engine source (LITE).
        wordlists\ tools\   staged data + embedded-binary dirs (Phase 4).

    The folder-bundle is the VALIDATED intermediate. Passing -OneFile builds the
    long-term distribution target (a single adscan.exe) on top of the SAME
    inputs, using adscan.windows.spec.

    Pinned + integrity-checked embeddable CPython mirrors the host-side
    build-mirror discipline (a pinned commit/version + a recorded sha256), so a
    silently-swapped interpreter fails the build instead of shipping.

    Idempotent, fail-fast, and echoes each step.

.PARAMETER OutDir
    Output bundle directory. Default: dist\adscan-windows.

.PARAMETER PythonVersion
    Embeddable CPython version to fetch. Default: 3.12.10.

.PARAMETER PythonSha256
    Expected sha256 of the embeddable zip. MUST be set to the real hash of the
    pinned download; the placeholder below fails the build unless -SkipHashCheck.

.PARAMETER OneFile
    Also build a onefile adscan.exe via adscan.windows.spec.

.PARAMETER SkipHashCheck
    Bypass the sha256 gate (dev only; NEVER in CI).

.EXAMPLE
    pwsh scripts\build_adscan_windows.ps1 -PythonSha256 <real-hash>

.EXAMPLE
    pwsh scripts\build_adscan_windows.ps1 -PythonSha256 <real-hash> -OneFile
#>

[CmdletBinding()]
param(
    [string]$OutDir = "dist/adscan-windows",
    [string]$PythonVersion = "3.12.10",
    # Pinned sha256 of python-3.12.10-embed-amd64.zip from python.org
    # (https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip).
    # If you bump -PythonVersion, pass the matching -PythonSha256 on the command
    # line (this default only matches 3.12.10).
    [string]$PythonSha256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3",
    [switch]$OneFile,
    [switch]$SkipHashCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Fail { param([string]$Message) Write-Error $Message; exit 1 }

# --------------------------------------------------------------------------
# Pinned third-party tool binaries (Phase 4).
#
# Every entry is a PINNED version + official Windows x64 download URL + a
# recorded sha256, mirroring the embeddable-CPython gate above. To bump a
# version: change the URL and the matching *_SHA256 constant here (one edit
# per tool), nothing else. Do NOT swap in an unpinned "-current" URL.
# --------------------------------------------------------------------------

# hashcat 6.2.6 (https://github.com/hashcat/hashcat/releases/tag/v6.2.6)
$HashcatVersion = "6.2.6"
$HashcatUrl     = "https://github.com/hashcat/hashcat/releases/download/v$HashcatVersion/hashcat-$HashcatVersion.7z"
$HashcatSha256  = "96697e9ef6a795d45863c91d61be85a9f138596e3151e7c2cd63ccf48aaa8783"

# John the Ripper 1.9.0-jumbo-1 win64 (https://www.openwall.com/john/)
$JohnUrl    = "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.7z"
$JohnSha256 = "ce05a898b72bb30c3c4f703e3ffcf25966c1b1801eb7e095030b44092ef92eaf"

# rclone 1.75.0 (https://github.com/rclone/rclone/releases/tag/v1.75.0)
$RcloneVersion = "1.75.0"
$RcloneUrl     = "https://github.com/rclone/rclone/releases/download/v$RcloneVersion/rclone-v$RcloneVersion-windows-amd64.zip"
$RcloneSha256  = "203581f0a7baeae873f2347483a798c79e2eaf5c384a4e9d866aa374f1c89ac0"

# kerbrute 1.0.3 (bare .exe — https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)
$KerbruteVersion = "1.0.3"
$KerbruteUrl     = "https://github.com/ropnop/kerbrute/releases/download/v$KerbruteVersion/kerbrute_windows_amd64.exe"
$KerbruteSha256  = "d18aa84b7bf0efde9c6b5db2a38ab1ec9484c59c5284c0bd080f5197bf9388b0"

# PKINITtools is a PYTHON project, NOT a compiled Windows binary. It ships as
# scripts (gettgtpkinit.py / getnthash.py) run by the embedded interpreter,
# staged from a pinned commit. There is no .exe to fetch — do not invent one.
$PkinitToolsRepo   = "https://github.com/dirkjanm/PKINITtools.git"
$PkinitToolsCommit = "0f0cfa542b0348609ad494713e84744234b2d3b0"

# OneRuleToRuleThemStill.rule — the full 48,414-rule set (effort-ladder top rung).
# Only the 10k prefix (OneRuleToRuleThemStill-10k.rule) is committed under
# adscan_internal/assets/rules/; the full rule is too large to commit and is a
# managed download. The Linux runtime resolves it from the managed rules dir
# (operator-installed, with a fallback to the bundled 10k). On Windows we fetch it
# at build time into the bundled assets/rules/ dir so the onefile .exe carries the
# top rung. Best-effort: if the fetch fails, the build continues and the effort
# ladder falls back to the committed 10k prefix (mirroring the Linux fallback).
# Upstream: https://github.com/stealthsploit/OneRuleToRuleThemStill
$OneRuleName = "OneRuleToRuleThemStill.rule"
$OneRuleUrl  = "https://raw.githubusercontent.com/stealthsploit/OneRuleToRuleThemStill/main/OneRuleToRuleThemStill.rule"
# TODO(pin): record the sha256 of the pinned commit's rule file and pin OneRuleUrl
# to that commit (not main) so the download is integrity-checked like the tool
# binaries above. Until then the fetch is best-effort (see Stage rules below).
$OneRuleSha256 = ""

function Get-PinnedFile {
    <#
      Download $Url into $OutFile (cached: reuse if present) and verify its
      sha256 against $Sha256. Fail-fast on mismatch. Idempotent.
    #>
    param(
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$OutFile,
        [Parameter(Mandatory)] [string]$Sha256,
        [string]$Label = ""
    )
    $name = if ($Label) { $Label } else { Split-Path -Leaf $OutFile }
    if (-not (Test-Path $OutFile)) {
        Write-Step "Downloading pinned $name"
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } else {
        Write-Step "Reusing cached $name"
    }
    if ($SkipHashCheck) {
        Write-Warning "sha256 gate BYPASSED for $name (-SkipHashCheck). Never do this in CI."
        return
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $OutFile).Hash.ToLower()
    if ($actual -ne $Sha256.ToLower()) {
        Fail "sha256 mismatch for $name. expected=$Sha256 actual=$actual"
    }
    Write-Step "Verified $name (sha256 ok)"
}

function Expand-Archive7z {
    <#
      Extract a .7z archive using an available 7-Zip CLI (7z / 7za / 7zr).
      hashcat and John ship as .7z, which Expand-Archive cannot read.
    #>
    param(
        [Parameter(Mandatory)] [string]$Archive,
        [Parameter(Mandatory)] [string]$DestDir
    )
    $sevenZip = $null
    foreach ($exe in @("7z", "7z.exe", "7za", "7za.exe", "7zr", "7zr.exe")) {
        $cmd = Get-Command $exe -ErrorAction SilentlyContinue
        if ($cmd) { $sevenZip = $cmd.Source; break }
    }
    if (-not $sevenZip) {
        Fail "A 7-Zip CLI (7z/7za/7zr) is required to extract $Archive but none was found on PATH. Install 7-Zip and retry."
    }
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    & $sevenZip x $Archive "-o$DestDir" -y | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "7-Zip extraction failed for $Archive (exit $LASTEXITCODE)." }
}

# Resolve the repo root (this script lives in scripts\).
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $RepoRoot
try {
    $Bundle = Join-Path $RepoRoot $OutDir
    $PyDir = Join-Path $Bundle "py"
    $SiteDir = Join-Path $Bundle "site"
    $VendorDir = Join-Path $Bundle "vendor"

    # The BUILD interpreter (a full CPython 3.12 with pip on PATH — e.g.
    # actions/setup-python) drives pip / playwright / PyInstaller. It is DISTINCT
    # from the embeddable python we unpack into py\ (the runtime, which ships no
    # pip). Both are CPython 3.12 so wheels are ABI-compatible.
    $BuildPy = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $BuildPy) { $BuildPy = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
    if (-not $BuildPy) { Fail "No build Python found on PATH (need a full CPython 3.12 with pip; e.g. actions/setup-python)." }
    Write-Step "Using build Python: $BuildPy"
    & $BuildPy -m pip --version
    if ($LASTEXITCODE -ne 0) { Fail "The build Python has no working pip: $BuildPy" }

    Write-Step "Repo root: $RepoRoot"
    Write-Step "Bundle out: $Bundle"

    # -- (a) Pinned + integrity-checked embeddable CPython -------------------
    $EmbedName = "python-$PythonVersion-embed-amd64.zip"
    $EmbedUrl = "https://www.python.org/ftp/python/$PythonVersion/$EmbedName"
    $CacheDir = Join-Path $env:LOCALAPPDATA "adscan\build-mirror"
    $EmbedZip = Join-Path $CacheDir "$EmbedName"

    New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
    if (-not (Test-Path $EmbedZip)) {
        Write-Step "Downloading pinned embeddable CPython $PythonVersion"
        Invoke-WebRequest -Uri $EmbedUrl -OutFile $EmbedZip -UseBasicParsing
    } else {
        Write-Step "Reusing cached $EmbedName"
    }

    if ($SkipHashCheck) {
        Write-Warning "sha256 gate BYPASSED (-SkipHashCheck). Never do this in CI."
    } elseif ([string]::IsNullOrWhiteSpace($PythonSha256) -or $PythonSha256 -eq "REPLACE_WITH_REAL_SHA256_OF_EMBEDDABLE_ZIP") {
        Fail "PythonSha256 is not set. Pin the real sha256 of $EmbedName (or pass -SkipHashCheck for a dev run)."
    } else {
        Write-Step "Verifying embeddable CPython sha256"
        $actual = (Get-FileHash -Algorithm SHA256 -Path $EmbedZip).Hash.ToLower()
        if ($actual -ne $PythonSha256.ToLower()) {
            Fail "sha256 mismatch for $EmbedName. expected=$PythonSha256 actual=$actual"
        }
    }

    Write-Step "Reset bundle dir"
    if (Test-Path $Bundle) { Remove-Item -Recurse -Force $Bundle }
    New-Item -ItemType Directory -Force -Path $PyDir | Out-Null
    Expand-Archive -Path $EmbedZip -DestinationPath $PyDir -Force

    # -- (b) Create site\ and pip install the project + deps ------------------
    New-Item -ItemType Directory -Force -Path $SiteDir | Out-Null
    Write-Step "pip install project + deps into site\ (from pyproject.toml/uv.lock)"
    # IMPORTANT: install with the BUILD Python (a full CPython with pip on PATH,
    # e.g. actions/setup-python), NOT the embeddable python we just unpacked into
    # py\. The Windows embeddable distribution ships WITHOUT pip and does not load
    # a get-pip'd pip cleanly ("No module named pip"), so using it here silently
    # left site\ EMPTY and PyInstaller later failed for missing deps. The
    # embeddable is the RUNTIME interpreter for the bundle; the build interpreter
    # ($BuildPy, resolved at the top) is what assembles site\. Both are CPython
    # 3.12 → the cp312 win_amd64 wheels pip resolves are ABI-correct.
    # The project's runtime deps (cli extra) unpacked into site\. Fail-fast: an
    # empty site\ is a broken bundle, not a warning.
    & $BuildPy -m pip install --target $SiteDir ".[cli]"
    if ($LASTEXITCODE -ne 0) { Fail "pip install .[cli] --target site\ failed (exit $LASTEXITCODE)." }
    if (-not (Get-ChildItem -Path $SiteDir -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        Fail "site\ is empty after pip install — no dependencies were staged."
    }
    # The vendored editable native stack, installed as plain packages into site\
    # is NOT needed — the ._pth exposes vendor\<lib> directly. We only need the
    # transitive pure-python deps, which ".[cli]" above pulls in.

    # Harden against Windows Defender: remove site\impacket\examples\.
    # Defender's real-time engine (on by default) quarantines impacket's
    # examples/ scripts (ntlmrelayx.py / dcsync.py / atexec.py / secretsdump.py)
    # on sight, and the quarantine can cascade to deleting impacket\__init__.py,
    # which breaks "from impacket import tds" (MSSQL) at runtime. ADscan imports
    # only impacket.tds / .ntlm / .structure — never examples/ — so deleting it
    # shrinks the AV surface with ZERO capability loss. Confirmed live on a
    # Windows Server 2016 test host (Defender deleted impacket files under the
    # bundle). Best-effort: absent examples/ (already stripped, or a slimmer
    # wheel) is not an error.
    Write-Step "Remove site\impacket\examples\ (Windows Defender AV hardening)"
    $ImpacketExamples = Join-Path $SiteDir "impacket\examples"
    if (Test-Path $ImpacketExamples) {
        Remove-Item -Recurse -Force $ImpacketExamples
    }

    # -- (c) Copy vendor\ and the engine source (LITE: exclude pro\) ---------
    Write-Step "Copy vendored native stack"
    New-Item -ItemType Directory -Force -Path $VendorDir | Out-Null
    foreach ($lib in @("aardwolf","aiosmb","asysocks","badauth","badldap","kerbad","pypykatz","winacl")) {
        Copy-Item -Recurse -Force (Join-Path $RepoRoot "vendor\$lib") (Join-Path $VendorDir $lib)
    }

    Write-Step "Copy engine source (LITE)"
    Copy-Item -Force (Join-Path $RepoRoot "adscan.py") (Join-Path $Bundle "adscan.py")
    Copy-Item -Recurse -Force (Join-Path $RepoRoot "adscan_core") (Join-Path $Bundle "adscan_core")
    Copy-Item -Recurse -Force (Join-Path $RepoRoot "adscan_internal") (Join-Path $Bundle "adscan_internal")
    # LITE strips pro\ — remove it after copy.
    $ProDir = Join-Path $Bundle "adscan_internal\pro"
    if (Test-Path $ProDir) {
        Write-Step "Strip pro\ (LITE)"
        Remove-Item -Recurse -Force $ProDir
    }

    # -- (d) Write py\python312._pth with the exact validated lines ----------
    # Relative to the py\ dir: '..' is the bundle root.
    Write-Step "Write py\python312._pth"
    $pthLines = @(
        "python312.zip",
        ".",
        "#import site",
        ".",
        "..",
        "../site",
        "../vendor/aardwolf",
        "../vendor/aiosmb",
        "../vendor/asysocks",
        "../vendor/badauth",
        "../vendor/badldap",
        "../vendor/kerbad",
        "../vendor/pypykatz",
        "../vendor/winacl",
        "import site"
    )
    $pthPath = Join-Path $PyDir "python312._pth"
    Set-Content -Path $pthPath -Value $pthLines -Encoding ascii

    # -- (e) Stage wordlists\ and tools\ (Phase 4 embedded binaries) ---------
    Write-Step "Stage wordlists\ and tools\"
    $WordlistsDir = Join-Path $Bundle "wordlists"
    $ToolsDir = Join-Path $Bundle "tools"
    New-Item -ItemType Directory -Force -Path $WordlistsDir | Out-Null
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    if (Test-Path (Join-Path $RepoRoot "wordlists")) {
        Copy-Item -Recurse -Force (Join-Path $RepoRoot "wordlists\*") $WordlistsDir
    }

    # Fetch the audit-base COMPONENTS from the manifest so the merge below has
    # something to merge. The big lists (hashmob_large / kaonashi14M / kerberoast_pws)
    # are gitignored and never reach the CI checkout, so without
    # this step the merge finds nothing and the bundle silently ships rockyou-only.
    # This calls the SHARED cross-platform preparer — the SAME script the Linux
    # Docker build uses — so Windows and Linux fetch/verify/extract identically
    # (xz via stdlib lzma, 7z via the 7-Zip CLI already required here). The bundle
    # dir is the context: the preparer writes into <Bundle>\wordlists\.
    # Best-effort: on a network/component failure the build continues and the
    # merge falls back to rockyou-only, mirroring the Linux fallback.
    $PrepScript = Join-Path $RepoRoot "scripts\prepare_runtime_wordlists.py"
    if (Test-Path $PrepScript) {
        Write-Step "Fetch audit-base wordlist components (shared cross-platform preparer)"
        try {
            & $BuildPy $PrepScript --context $Bundle --manifest (Join-Path $WordlistsDir "manifest.json")
            if ($LASTEXITCODE -ne 0) {
                Write-Warning ("Wordlist component preparation reported missing components " +
                               "(exit $LASTEXITCODE) — the combined merge will fall back to rockyou-only.")
            }
        } catch {
            Write-Warning ("Wordlist component preparation failed (non-fatal): " +
                           $_.Exception.Message + " — combined merge falls back to rockyou-only.")
        }
    } else {
        Write-Warning "scripts\prepare_runtime_wordlists.py not found; combined merge will have no components to merge."
    }

    # Build combined_audit_base.txt from the staged components (priority-concat +
    # order-preserving dedup), mirroring the Linux runtime image's audit base
    # (scripts/build_combined_audit_wordlist.sh). Best-effort: a build without the
    # heavy components still ships a working bundle (rockyou-only) — the merge
    # script logs and exits 0 when components are absent, and we never fail the
    # whole Windows build on it. -DropRawComponents ships only the single combined
    # file, matching the Linux combined-only ship.
    Write-Step "Build combined_audit_base.txt (order-preserving merge)"
    $CombineScript = Join-Path $RepoRoot "scripts\build_combined_audit_wordlist.ps1"
    if (Test-Path $CombineScript) {
        try {
            & $CombineScript -WordlistsDir $WordlistsDir -DropRawComponents
        } catch {
            Write-Warning ("Combined audit wordlist build failed (non-fatal): " +
                           $_.Exception.Message + " — bundle ships without the combined base.")
        }
    } else {
        Write-Warning "scripts\build_combined_audit_wordlist.ps1 not found; skipping combined merge."
    }

    # Compress the merged combined_audit_base.txt with xz (stdlib lzma via the
    # build Python — no external xz binary needed) so the onefile .exe ships the
    # ~928MB base as a ~310MB .xz (~3.0x), keeping the download near ~500MB
    # instead of ~1.2GB. The frozen runtime decompresses it ONCE into LOCALAPPDATA
    # on first use (cracking_wordlist_policy._decompress_bundled_xz_once) and
    # reuses the plain .txt after. We ship the .xz ONLY (drop the raw .txt) so the
    # bundle carries the compressed variant, not both. Best-effort: on any failure
    # the raw .txt is left in place and bundled uncompressed (bigger .exe, still
    # correct) — a compression hiccup never fails the whole Windows build.
    Write-Step "Compress combined_audit_base.txt (xz, drop raw)"
    $CombinedTxt = Join-Path $WordlistsDir "combined_audit_base.txt"
    if (Test-Path $CombinedTxt) {
        try {
            $CompressPy = @'
import lzma, os, shutil, sys
src = sys.argv[1]
dst = src + ".xz"
with open(src, "rb") as fin, lzma.open(dst, "wb", preset=6) as fout:
    shutil.copyfileobj(fin, fout, length=8 * 1024 * 1024)
os.remove(src)
print("compressed %s -> %s (%d -> %d bytes)" % (
    os.path.basename(src), os.path.basename(dst),
    0, os.path.getsize(dst)))
'@
            & $BuildPy -c $CompressPy $CombinedTxt
            if ($LASTEXITCODE -ne 0) {
                Write-Warning ("xz compression of combined_audit_base.txt failed " +
                               "(exit $LASTEXITCODE) — the bundle ships the raw .txt.")
            }
        } catch {
            Write-Warning ("xz compression of combined_audit_base.txt failed " +
                           "(non-fatal): " + $_.Exception.Message +
                           " — the bundle ships the raw .txt.")
        }
    } else {
        Write-Step "No combined_audit_base.txt to compress (merge produced none)"
    }

    # Fetch the full 48k OneRuleToRuleThemStill.rule (effort-ladder top rung) into
    # the bundled assets/rules/ dir. Only the 10k prefix is committed; the full
    # rule is a managed download. Best-effort — on failure the effort ladder falls
    # back to the committed 10k prefix (mirroring the Linux managed-rule fallback).
    Write-Step "Stage full OneRuleToRuleThemStill.rule (48k top rung)"
    $RulesAssetDir = Join-Path $Bundle "adscan_internal\assets\rules"
    $OneRuleDest = Join-Path $RulesAssetDir $OneRuleName
    New-Item -ItemType Directory -Force -Path $RulesAssetDir | Out-Null
    if (Test-Path $OneRuleDest) {
        Write-Step "OneRuleToRuleThemStill.rule already staged"
    } else {
        $OneRuleCache = Join-Path $CacheDir $OneRuleName
        try {
            if ($OneRuleSha256) {
                Get-PinnedFile -Url $OneRuleUrl -OutFile $OneRuleCache -Sha256 $OneRuleSha256 -Label $OneRuleName
            } else {
                # No pinned sha256 yet (TODO above) — download best-effort, unverified.
                if (-not (Test-Path $OneRuleCache)) {
                    Invoke-WebRequest -Uri $OneRuleUrl -OutFile $OneRuleCache -UseBasicParsing
                }
                Write-Warning "OneRuleToRuleThemStill.rule fetched WITHOUT a sha256 gate (unpinned). Pin it (TODO in this script)."
            }
            Copy-Item -Force $OneRuleCache $OneRuleDest
            Write-Step "Staged $OneRuleName into assets\rules\"
        } catch {
            Write-Warning ("Could not fetch $OneRuleName (non-fatal): " +
                           $_.Exception.Message + " — effort ladder falls back to the committed 10k rule.")
        }
    }

    # -- Phase 4: fetch the pinned tool binaries + Chromium into tools\ ------
    # Each download is pinned (URL + sha256 constants at the top of this script)
    # and verified before use, mirroring the embeddable-CPython gate. Downloads
    # are cached under $CacheDir; staging into tools\ is idempotent (each tool
    # dir is reset before extraction). A hash mismatch fails the build.
    $DlDir = Join-Path $CacheDir "phase4"
    New-Item -ItemType Directory -Force -Path $DlDir | Out-Null

    # hashcat (.7z) -> tools\hashcat\  (needed: hashcat-<ver>\hashcat.exe + its
    # OpenCL/ data dirs, so the WHOLE extracted tree is kept).
    Write-Step "Stage hashcat $HashcatVersion"
    $HashcatArchive = Join-Path $DlDir "hashcat-$HashcatVersion.7z"
    Get-PinnedFile -Url $HashcatUrl -OutFile $HashcatArchive -Sha256 $HashcatSha256 -Label "hashcat $HashcatVersion"
    $HashcatOut = Join-Path $ToolsDir "hashcat"
    if (Test-Path $HashcatOut) { Remove-Item -Recurse -Force $HashcatOut }
    Expand-Archive7z -Archive $HashcatArchive -DestDir $HashcatOut
    # Sanity: hashcat-<ver>\hashcat.exe must exist inside the extracted tree.
    if (-not (Test-Path (Join-Path $HashcatOut "hashcat-$HashcatVersion\hashcat.exe"))) {
        Fail "hashcat.exe not found under $HashcatOut after extraction."
    }

    # John the Ripper jumbo (.7z) -> tools\john\. The WHOLE run\ dir must be
    # bundled: run\john.exe plus its cygwin runtime DLLs (cyg*.dll) live there.
    Write-Step "Stage John the Ripper (jumbo, win64)"
    $JohnArchive = Join-Path $DlDir "john-1.9.0-jumbo-1-win64.7z"
    Get-PinnedFile -Url $JohnUrl -OutFile $JohnArchive -Sha256 $JohnSha256 -Label "John the Ripper 1.9.0-jumbo-1"
    $JohnOut = Join-Path $ToolsDir "john"
    if (Test-Path $JohnOut) { Remove-Item -Recurse -Force $JohnOut }
    Expand-Archive7z -Archive $JohnArchive -DestDir $JohnOut
    if (-not (Test-Path (Join-Path $JohnOut "john-1.9.0-jumbo-1-win64\run\john.exe"))) {
        Fail "john.exe not found under $JohnOut\...\run after extraction."
    }

    # rclone (.zip) -> tools\rclone\rclone.exe (flattened out of the versioned
    # subdir so the launcher finds tools\rclone\rclone.exe).
    Write-Step "Stage rclone $RcloneVersion"
    $RcloneArchive = Join-Path $DlDir "rclone-v$RcloneVersion-windows-amd64.zip"
    Get-PinnedFile -Url $RcloneUrl -OutFile $RcloneArchive -Sha256 $RcloneSha256 -Label "rclone $RcloneVersion"
    $RcloneOut = Join-Path $ToolsDir "rclone"
    if (Test-Path $RcloneOut) { Remove-Item -Recurse -Force $RcloneOut }
    New-Item -ItemType Directory -Force -Path $RcloneOut | Out-Null
    $RcloneTmp = Join-Path $DlDir "rclone-extract"
    if (Test-Path $RcloneTmp) { Remove-Item -Recurse -Force $RcloneTmp }
    Expand-Archive -Path $RcloneArchive -DestinationPath $RcloneTmp -Force
    $RcloneExe = Join-Path $RcloneTmp "rclone-v$RcloneVersion-windows-amd64\rclone.exe"
    if (-not (Test-Path $RcloneExe)) { Fail "rclone.exe not found in $RcloneArchive after extraction." }
    Copy-Item -Force $RcloneExe (Join-Path $RcloneOut "rclone.exe")
    Remove-Item -Recurse -Force $RcloneTmp

    # kerbrute (bare .exe) -> tools\kerbrute\kerbrute.exe (no archive).
    Write-Step "Stage kerbrute $KerbruteVersion"
    $KerbruteOut = Join-Path $ToolsDir "kerbrute"
    if (Test-Path $KerbruteOut) { Remove-Item -Recurse -Force $KerbruteOut }
    New-Item -ItemType Directory -Force -Path $KerbruteOut | Out-Null
    $KerbruteExe = Join-Path $KerbruteOut "kerbrute.exe"
    Get-PinnedFile -Url $KerbruteUrl -OutFile $KerbruteExe -Sha256 $KerbruteSha256 -Label "kerbrute $KerbruteVersion"

    # PKINITtools (PYTHON scripts, not a binary) -> tools\PKINITtools\.
    # Cloned at a pinned commit and run by the embedded interpreter. If the repo
    # already carries a copy under reference\ / vendor\, prefer that; otherwise
    # clone the pinned commit. git is required only for this step.
    Write-Step "Stage PKINITtools (Python scripts @ $PkinitToolsCommit)"
    $PkinitOut = Join-Path $ToolsDir "PKINITtools"
    if (Test-Path $PkinitOut) { Remove-Item -Recurse -Force $PkinitOut }
    $PkinitLocal = Join-Path $RepoRoot "reference\PKINITtools"
    if (Test-Path (Join-Path $PkinitLocal "gettgtpkinit.py")) {
        Write-Step "Copying PKINITtools from reference\PKINITtools"
        Copy-Item -Recurse -Force $PkinitLocal $PkinitOut
    } else {
        $git = Get-Command git -ErrorAction SilentlyContinue
        if (-not $git) {
            Fail "PKINITtools is not under reference\PKINITtools and git is not on PATH. Install git or vendor PKINITtools at commit $PkinitToolsCommit."
        }
        $PkinitTmp = Join-Path $DlDir "PKINITtools-clone"
        if (Test-Path $PkinitTmp) { Remove-Item -Recurse -Force $PkinitTmp }
        & git clone $PkinitToolsRepo $PkinitTmp
        if ($LASTEXITCODE -ne 0) { Fail "git clone of PKINITtools failed." }
        & git -C $PkinitTmp checkout --quiet $PkinitToolsCommit
        if ($LASTEXITCODE -ne 0) { Fail "git checkout of PKINITtools commit $PkinitToolsCommit failed." }
        Remove-Item -Recurse -Force (Join-Path $PkinitTmp ".git")
        Copy-Item -Recurse -Force $PkinitTmp $PkinitOut
        Remove-Item -Recurse -Force $PkinitTmp
    }
    if (-not (Test-Path (Join-Path $PkinitOut "gettgtpkinit.py"))) {
        Fail "gettgtpkinit.py not found under $PkinitOut after staging."
    }

    # Chromium for Playwright. Playwright pins its own Chromium revision for the
    # installed playwright wheel (==1.60.0, from pyproject.toml), so there is no
    # stable direct-download URL to pin here — the canonical, version-correct way
    # is to let Playwright fetch the matching build. Point it at the bundle's
    # tools\ms-playwright, which the Windows runtime hook
    # (pyinstaller_runtime_hook_playwright_windows.py) resolves at launch.
    Write-Step "Install Playwright-pinned Chromium into tools\ms-playwright"
    $MsPlaywrightDir = Join-Path $ToolsDir "ms-playwright"
    New-Item -ItemType Directory -Force -Path $MsPlaywrightDir | Out-Null
    $env:PLAYWRIGHT_BROWSERS_PATH = $MsPlaywrightDir
    # playwright was installed into site\ via --target, NOT into the build python,
    # so `$BuildPy -m playwright` alone raises "No module named playwright". Point
    # PYTHONPATH at site\ so the build interpreter can run the bundle's OWN pinned
    # playwright CLI (==1.60.0) — which downloads the Chromium revision matched to
    # that exact wheel into tools\ms-playwright.
    $prevPyPath = $env:PYTHONPATH
    $env:PYTHONPATH = if ($prevPyPath) { "$SiteDir$([IO.Path]::PathSeparator)$prevPyPath" } else { $SiteDir }
    try {
        & $BuildPy -m playwright install chromium
        $pwExit = $LASTEXITCODE
    } finally {
        $env:PYTHONPATH = $prevPyPath
    }
    if ($pwExit -ne 0) {
        Fail "playwright install chromium failed (exit $pwExit). PDF rendering needs Chromium under tools\ms-playwright."
    }

    # RDP-optional: arc4 + the bitstruct C accelerator were NOT in the working
    # bundle and RDP degraded gracefully. Add them (pip wheels) only if full RDP
    # is required.

    Write-Step "Folder bundle assembled: $Bundle"

    # -- (f) Optional onefile build ------------------------------------------
    if ($OneFile) {
        Write-Step "Building onefile adscan.exe via adscan.windows.spec"
        # Staged wordlists\ / tools\ next to the spec so its datas/binaries globs
        # pick them up. Run from the repo root where adscan.windows.spec lives.
        #
        # The deps were pip-installed into $SiteDir (--target), NOT into the
        # build Python's site-packages. PyInstaller's Analysis runs under the
        # build Python, so it can only import those deps (rich/questionary/…) if
        # $SiteDir is on its analysis path. Export it for the spec's pathex —
        # without this the onefile .exe dies at startup with
        # "ModuleNotFoundError: No module named 'rich'".
        $env:ADSCAN_WIN_SITE = $SiteDir
        # PyInstaller runs from the repo root, but the merged combined wordlist and
        # the staged tools live in the BUNDLE dir (not the repo's gitignored
        # ./wordlists, which in CI holds only rockyou). Point the spec at the bundle
        # dirs so the 94M-line combined is actually embedded into the onefile.
        $env:ADSCAN_WIN_WORDLISTS = $WordlistsDir
        $env:ADSCAN_WIN_TOOLS = $ToolsDir
        Write-Step "PyInstaller analysis path (deps): $SiteDir"
        Write-Step "PyInstaller wordlists: $WordlistsDir  tools: $ToolsDir"
        & $BuildPy -m PyInstaller "adscan.windows.spec" --noconfirm
        Write-Step "onefile build finished (see dist\adscan.exe)"
    }

    Write-Step "Done."
}
finally {
    Pop-Location
}
