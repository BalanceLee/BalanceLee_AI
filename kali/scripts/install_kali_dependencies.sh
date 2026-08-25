#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/kali-tools.json"
PROFILES="core,web"
APPLY=0
UPDATE=0
WITH_OPTIONAL_PYTHON=0
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv-kali}"

usage() {
  cat <<'EOF'
Usage: scripts/install_kali_dependencies.sh [options]

Default behavior is DRY-RUN. Nothing is installed unless --apply is supplied.

Options:
  --profiles core,web     Tool profiles to install (default: core,web)
  --all                   Install apt packages from all profiles
  --apply                 Execute apt/pip/playwright commands
  --update                Run apt update before installation
  --with-optional-python  Also install requirements-kali-optional.txt
  --python PATH           Python executable used to create the venv
  --venv PATH             Virtual environment path
  -h, --help              Show this help

Notes:
  - apt package availability changes across Kali rolling releases. Each apt
    package is installed separately; unavailable packages are reported but do
    not stop the whole installation.
  - Tools in kali-tools.json external_install_notes are NOT blindly installed.
    Use their official release or isolated installer, then rerun the checker.
  - Use only in an authorized lab environment.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profiles) PROFILES="$2"; shift 2 ;;
    --all) PROFILES="all"; shift ;;
    --apply) APPLY=1; shift ;;
    --update) UPDATE=1; shift ;;
    --with-optional-python) WITH_OPTIONAL_PYTHON=1; shift ;;
    --python) PYTHON_BIN="$2"; shift 2 ;;
    --venv) VENV_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 2
fi

APT_PACKAGES=()
while IFS= read -r package; do
  [[ -n "$package" ]] && APT_PACKAGES+=("$package")
done < <("$PYTHON_BIN" - "$MANIFEST" "$PROFILES" <<'PY'
import json, sys
path, raw = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
available = data["apt_packages"]
profiles = list(available) if raw == "all" else [x.strip() for x in raw.split(",") if x.strip()]
unknown = [x for x in profiles if x not in available]
if unknown:
    raise SystemExit("Unknown apt profiles: " + ", ".join(unknown))
seen = set()
for profile in profiles:
    for package in available[profile]:
        if package not in seen:
            seen.add(package)
            print(package)
PY
)

run() {
  if [[ "$APPLY" -eq 1 ]]; then
    "$@"
  else
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  fi
}

echo "HexStrike Kali dependency installer"
echo "  Root:     $ROOT_DIR"
echo "  Profiles: $PROFILES"
echo "  Venv:     $VENV_DIR"
echo "  Mode:     $([[ "$APPLY" -eq 1 ]] && echo APPLY || echo DRY-RUN)"
echo

if [[ "$UPDATE" -eq 1 ]]; then
  run sudo apt-get update
fi

for package in "${APT_PACKAGES[@]}"; do
  if [[ "$APPLY" -eq 1 ]]; then
    echo "[apt] Installing $package"
    if ! sudo apt-get install -y "$package"; then
      echo "[warn] apt package unavailable or failed: $package" >&2
    fi
  else
    run sudo apt-get install -y "$package"
  fi
done

run "$PYTHON_BIN" -m venv "$VENV_DIR"
if [[ "$APPLY" -eq 1 ]]; then
  VENV_PYTHON="$VENV_DIR/bin/python"
else
  VENV_PYTHON="$VENV_DIR/bin/python"
fi
run "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel
run "$VENV_PYTHON" -m pip install -r "$ROOT_DIR/requirements-kali.txt"
if [[ "$WITH_OPTIONAL_PYTHON" -eq 1 ]]; then
  run "$VENV_PYTHON" -m pip install -r "$ROOT_DIR/requirements-kali-optional.txt"
fi
run "$VENV_PYTHON" -m playwright install chromium

echo
if [[ "$APPLY" -eq 0 ]]; then
  echo "Dry-run complete. Re-run with --apply to install."
else
  echo "Installation phase complete. Validate with:"
  echo "  $VENV_PYTHON $ROOT_DIR/scripts/check_kali_dependencies.py --profiles $PROFILES"
  echo "Review kali-tools.json external_install_notes for tools not provided by apt."
fi
