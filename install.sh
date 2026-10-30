#!/usr/bin/env bash
# Instala el Quality Gate Kit (qgate) en un proyecto Linux, sin privilegios de root.
# Uso: ./install.sh [ruta_proyecto] [version_python]
# Respeta HTTP_PROXY / HTTPS_PROXY (pip y curl los usan automáticamente).
set -euo pipefail

PROJECT="${1:-$PWD}"
PY_VERSION="${2:-3.12}"
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITLEAKS_VERSION="8.21.2"
declare -A GITLEAKS_SHA=(
  [x64]="5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba"
  [arm64]="654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da"
)

step() { printf '\033[36m==> %s\033[0m\n' "$*"; }

cd "$PROJECT"
step "Proyecto: $PWD"

PYTHON="$(command -v "python$PY_VERSION" || command -v python3)"
if [ ! -x .venv/bin/python ]; then
  step "Creando .venv con $PYTHON"
  "$PYTHON" -m venv .venv
fi

step "Instalando herramientas fijadas (requirements-dev.lock) y qgate"
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r "$KIT/requirements-dev.lock"
.venv/bin/python -m pip install "$KIT"
if [ -f requirements.txt ]; then
  step "Instalando dependencias del proyecto (requirements.txt)"
  .venv/bin/python -m pip install -r requirements.txt
fi

if [ ! -x .qgate/bin/gitleaks ]; then
  arch="x64"; case "$(uname -m)" in aarch64|arm64) arch="arm64";; esac
  asset="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"
  step "Descargando $asset"
  mkdir -p .qgate/bin
  if curl -fsSL -o ".qgate/bin/$asset" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$asset"; then
    echo "${GITLEAKS_SHA[$arch]}  .qgate/bin/$asset" | sha256sum -c -
    tar -xzf ".qgate/bin/$asset" -C .qgate/bin gitleaks
    rm -f ".qgate/bin/$asset"
  else
    echo "AVISO: no se pudo descargar gitleaks; qgate usará detect-secrets." >&2
  fi
fi

if [ -d .git ] && [ -f .pre-commit-config.yaml ]; then
  step "Instalando hooks de pre-commit"
  .venv/bin/pre-commit install --hook-type pre-commit --hook-type pre-push
elif [ ! -f qgate.toml ]; then
  echo "Sugerencia: ejecute '.venv/bin/qgate init .' para generar qgate.toml y los hooks."
fi

step "qgate doctor"
.venv/bin/qgate doctor || true
echo "Listo. Active el entorno con 'source .venv/bin/activate' y ejecute: qgate run --level fast"
