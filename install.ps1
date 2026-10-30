<#
.SYNOPSIS
  Instala el Quality Gate Kit (qgate) en un proyecto, sin permisos de administrador.

.DESCRIPTION
  1. Crea .venv en el proyecto con el Python indicado.
  2. Instala las herramientas EXACTAS de requirements-dev.lock y el kit.
  3. Descarga gitleaks para Windows a .qgate\bin verificando su SHA-256.
  4. Instala los hooks de pre-commit (fast en commit, standard en pre-push).
  5. Ejecuta qgate doctor.
  Respeta HTTP_PROXY / HTTPS_PROXY si están definidas.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -ProjectPath C:\apps\mi_dashboard -PythonVersion 3.12
#>
param(
    [string]$ProjectPath = (Get-Location).Path,
    [string]$PythonVersion = "3.12",
    [string]$PythonExe = "",
    [string]$KitSource = $PSScriptRoot,
    [switch]$SkipHooks
)

$ErrorActionPreference = "Stop"
$GitleaksVersion = "8.21.2"
$GitleaksSha256 = "f238c85e5f47e18fac779ce71ee11091cf70a0a8fb4415f165efba2800eef133"

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

$ProjectPath = (Resolve-Path $ProjectPath).Path
Set-Location $ProjectPath
Write-Step "Proyecto: $ProjectPath"

# --- Proxy corporativo -------------------------------------------------------
$proxy = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } elseif ($env:HTTP_PROXY) { $env:HTTP_PROXY } else { "" }
$webArgs = @{ UseBasicParsing = $true }
if ($proxy) {
    Write-Step "Usando proxy $proxy"
    $webArgs["Proxy"] = $proxy
    $webArgs["ProxyUseDefaultCredentials"] = $true
}

# --- 1. Entorno virtual ------------------------------------------------------
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    # Windows PowerShell 5.1 convierte el stderr redirigido en error terminante con "Stop".
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (@($output) -join "`n") }
    } catch {
        return [pscustomobject]@{ Code = 9009; Output = "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Resolve-Python {
    # Devuelve la ruta de un python.exe >= 3.11 con venv y ensurepip, o falla explicando por qué.
    $probe = @("-c", "import sys, venv, ensurepip; print(sys.executable); print('%d.%d' % sys.version_info[:2])")
    if ($PythonExe) {
        $exe = $PythonExe; $prefix = @()
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $exe = "py"; $prefix = @("-$PythonVersion")
    } else {
        $exe = "python"; $prefix = @()
    }
    $result = Invoke-Native $exe ($prefix + $probe)
    if ($result.Code -ne 0) {
        if ($exe -eq "py") {
            $installed = (Invoke-Native "py" @("-0p")).Output
            $hint = "Versiones instaladas según 'py -0p':`n$installed`n" +
                    "Repita con -PythonVersion <una de ellas, >= 3.11> o con -PythonExe <ruta a python.exe>."
        } else {
            $hint = "Instale Python >= 3.11 desde python.org (el alias de Microsoft Store no sirve) " +
                    "o indique -PythonExe <ruta a python.exe>."
        }
        throw ("No se encontró un Python $PythonVersion utilizable ('$exe $($prefix -join ' ')').`n" +
               "Salida: $($result.Output)`n$hint`n" +
               "Si dice 'No module named venv' o 'ensurepip', ese Python no es una instalación completa " +
               "(p. ej. la versión 'embeddable'): use el instalador normal de python.org.")
    }
    $lines = @($result.Output -split "`n" | Where-Object { $_.Trim() })
    $found = $lines[-2].Trim()
    $version = $lines[-1].Trim()
    if ([version]$version -lt [version]"3.11") {
        throw "Python $version ($found) es demasiado antiguo: requirements-dev.lock exige Python >= 3.11."
    }
    if ($version -ne $PythonVersion) {
        Write-Warning "Se usará Python $version ($found), distinto de -PythonVersion $PythonVersion."
    }
    return $found
}

$venvPython = Join-Path $ProjectPath ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $python = Resolve-Python
    Write-Step "Creando .venv con $python"
    $result = Invoke-Native $python @("-m", "venv", (Join-Path $ProjectPath ".venv"))
    if ($result.Code -ne 0 -or -not (Test-Path $venvPython)) {
        throw ("No se pudo crear el entorno virtual con $python (código $($result.Code)).`n" +
               "Salida: $($result.Output)`n" +
               "Causas frecuentes: antivirus o política corporativa que bloquea ejecutables en la carpeta, " +
               "ruta sin permisos de escritura, o una carpeta .venv incompleta de un intento anterior " +
               "(bórrela y reintente).")
    }
}

# --- 2. Herramientas y kit -----------------------------------------------------
Write-Step "Instalando herramientas fijadas (requirements-dev.lock) y qgate"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $KitSource "requirements-dev.lock")
if ($LASTEXITCODE -ne 0) { throw "Falló la instalación de herramientas." }
& $venvPython -m pip install $KitSource
if ($LASTEXITCODE -ne 0) { throw "Falló la instalación de qgate." }
if (Test-Path (Join-Path $ProjectPath "requirements.txt")) {
    Write-Step "Instalando dependencias del proyecto (requirements.txt)"
    & $venvPython -m pip install -r (Join-Path $ProjectPath "requirements.txt")
}

# --- 3. gitleaks verificado ----------------------------------------------------
$binDir = Join-Path $ProjectPath ".qgate\bin"
$gitleaks = Join-Path $binDir "gitleaks.exe"
if (-not (Test-Path $gitleaks)) {
    Write-Step "Descargando gitleaks $GitleaksVersion"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $zip = Join-Path $binDir "gitleaks.zip"
    $url = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/gitleaks_${GitleaksVersion}_windows_x64.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip @webArgs
        $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
        if ($hash -ne $GitleaksSha256) { throw "Checksum inválido de gitleaks: $hash" }
        Expand-Archive -Path $zip -DestinationPath $binDir -Force
        Write-Step "gitleaks verificado (SHA-256) en $gitleaks"
    } catch {
        Write-Warning "No se pudo instalar gitleaks ($_). qgate usará detect-secrets como alternativa."
    } finally {
        Remove-Item $zip -ErrorAction SilentlyContinue
    }
}

# --- 4. Hooks de pre-commit -----------------------------------------------------
$qgate = Join-Path $ProjectPath ".venv\Scripts\qgate.exe"
if (-not $SkipHooks -and (Test-Path ".git") -and (Test-Path ".pre-commit-config.yaml")) {
    Write-Step "Instalando hooks de pre-commit"
    & (Join-Path $ProjectPath ".venv\Scripts\pre-commit.exe") install --hook-type pre-commit --hook-type pre-push
} elseif (-not (Test-Path "qgate.toml")) {
    Write-Host "Sugerencia: ejecute '$qgate init .' para generar qgate.toml y los hooks." -ForegroundColor Yellow
}

# --- 5. Diagnóstico -----------------------------------------------------------
Write-Step "qgate doctor"
& $qgate doctor
Write-Host "`nListo. Active el entorno con .\.venv\Scripts\Activate.ps1 y ejecute: qgate run --level fast" -ForegroundColor Green
