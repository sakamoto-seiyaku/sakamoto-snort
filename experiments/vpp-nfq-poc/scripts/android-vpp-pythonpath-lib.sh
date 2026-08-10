# shellcheck shell=bash

vpp_android_use_fallback_pythonpath() {
  local site_packages="$VPP_WORK_ROOT/s73-python-venv/lib/python3.13/site-packages"
  if [ -z "${PYTHONPATH:-}" ] && [ -d "$site_packages" ]; then
    export PYTHONPATH="$site_packages"
  fi
}
