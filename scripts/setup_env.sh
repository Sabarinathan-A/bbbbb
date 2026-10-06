#!/usr/bin/env bash
#
# setup_env.sh - reproducible, offline environment setup for the AttackPath Engine.
#
# PyPI is blocked in this sandbox, so the required pure-Python dependencies
# (networkx + the pytest toolchain) are vendored by directory copy from
# pre-cloned GitHub sources into the venv's site-packages. The local
# 'attackpath' package is then editable-installed (that works because it is a
# local path with no un-vendored dependencies).
#
# Idempotent and safe to re-run. Override the vendoring source base with
# VENDOR_SRC (defaults to /projects/sandbox).
set -euo pipefail

# Resolve the repo root (parent of this script's dir) so the script works
# regardless of the current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
VENDOR_SRC="${VENDOR_SRC:-/projects/sandbox}"

echo "==> Repo root:    ${REPO_ROOT}"
echo "==> Vendor source: ${VENDOR_SRC}"

# (a) Create the venv (idempotent: reuse an existing one).
if [ ! -x "${VENV_DIR}/bin/python" ]; then
    echo "==> Creating venv at ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
else
    echo "==> Reusing existing venv at ${VENV_DIR}"
fi

VENV_PY="${VENV_DIR}/bin/python"

# (b) Resolve the venv site-packages directory via the venv python.
SP="$("${VENV_PY}" -c 'import site; print(site.getsitepackages()[0])')"
echo "==> Site-packages: ${SP}"
mkdir -p "${SP}"

# (c) Copy the pure-Python dependency package directories into site-packages.
# copy_dir SRC DEST_NAME: copy a directory (replacing any existing copy).
copy_dir() {
    local src="$1"
    local name="$2"
    if [ ! -e "${src}" ]; then
        echo "ERROR: vendoring source not found: ${src}" >&2
        exit 1
    fi
    rm -rf "${SP:?}/${name}"
    cp -r "${src}" "${SP}/${name}"
    echo "    copied ${name}"
}

echo "==> Vendoring dependencies"
copy_dir "${VENDOR_SRC}/nx-src/networkx"                   "networkx"
copy_dir "${VENDOR_SRC}/src-pytest/src/_pytest"            "_pytest"
copy_dir "${VENDOR_SRC}/src-pytest/src/pytest"             "pytest"
copy_dir "${VENDOR_SRC}/src-pluggy/src/pluggy"             "pluggy"
copy_dir "${VENDOR_SRC}/src-iniconfig/src/iniconfig"       "iniconfig"
copy_dir "${VENDOR_SRC}/src-tomli/src/tomli"               "tomli"
copy_dir "${VENDOR_SRC}/src-packaging/src/packaging"       "packaging"
copy_dir "${VENDOR_SRC}/src-exceptiongroup/src/exceptiongroup" "exceptiongroup"

# py.py is a single-file module shim shipped alongside pytest.
if [ ! -e "${VENDOR_SRC}/src-pytest/src/py.py" ]; then
    echo "ERROR: vendoring source not found: ${VENDOR_SRC}/src-pytest/src/py.py" >&2
    exit 1
fi
cp "${VENDOR_SRC}/src-pytest/src/py.py" "${SP}/py.py"
echo "    copied py.py"

# (d) Write the static version files. These packages normally derive their
# version from setuptools_scm and have no static version file when copied, so
# imports fail without them.
cat > "${SP}/_pytest/_version.py" <<'EOF'
version = '7.4.4'
__version__ = '7.4.4'
version_tuple = (7, 4, 4)
EOF
echo "    wrote _pytest/_version.py"

cat > "${SP}/exceptiongroup/_version.py" <<'EOF'
version = '1.2.0'
__version__ = '1.2.0'
EOF
echo "    wrote exceptiongroup/_version.py"

# (e) Editable install of the local attackpath package. networkx is already
# satisfied by the copied package, so --no-deps keeps pip from reaching the
# (blocked) PyPI. --no-use-pep517 forces the legacy 'setup.py develop' path
# (metadata comes from setup.cfg via the setup.py shim), which only needs the
# already-present setuptools; the modern PEP 517/660 build would otherwise fail
# because the venv's pip (21.3.1) has no 'wheel' package for 'bdist_wheel'. This
# works only because pyproject.toml declares no [build-system] backend.
echo "==> Installing attackpath (editable)"
"${VENV_PY}" -m pip install --no-use-pep517 --no-build-isolation --no-deps -e "${REPO_ROOT}"

# (f) Self-check.
echo "==> Self-check"
"${VENV_PY}" -m pytest --version
"${VENV_PY}" -c "import attackpath, networkx; print('attackpath', attackpath.__version__); print('networkx', networkx.__version__)"

echo "==> Done. Activate with: source ${VENV_DIR}/bin/activate"
