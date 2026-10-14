#!/bin/bash
# record_build.sh — snapshot everything needed to reproduce a BKC build.
# Usage: ./record_build.sh <kext_list> <path/to/output.kc>
# Writes a timestamped manifest to ./build_manifests/.

set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <kext_list> <path/to/output.kc>" >&2
  exit 1
fi

KERNEL="${KERNEL:-/System/Library/Kernels/kernel.release.t8112}"
KEXT_LIST="$1"
KC_OUT="$2"
[ -f "$KEXT_LIST" ] || { echo "kext list not found: $KEXT_LIST" >&2; exit 1; }
[ -f "$KC_OUT" ] || { echo "kernel collection not found: $KC_OUT" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="build_manifests"
MAN="$OUTDIR/manifest_$STAMP.txt"
mkdir -p "$OUTDIR"

sha() { [ -f "$1" ] && shasum -a 256 "$1" | awk '{print $1}' || echo "MISSING"; }

{
  echo "# BKC build manifest — $STAMP (UTC)"
  echo
  echo "## Host / OS"
  echo "hw.model            : $(sysctl -n hw.model)"
  echo "cpu                 : $(sysctl -n machdep.cpu.brand_string)"
  echo "product/build       : $(sw_vers -productVersion) / $(sw_vers -buildVersion)"
  echo "kernel version      : $(uname -v)"
  echo "SIP                 : $(csrutil status 2>/dev/null || echo 'n/a')"
  echo "boot-args           : $(nvram boot-args 2>/dev/null || echo '(none)')"
  echo
  echo "## Toolchain"
  echo "kmutil (ships w/OS) : $(sha "$(command -v kmutil)")  $(command -v kmutil)"
  echo "CLT                 : $(pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null | awk '/version/{print $2}' || echo 'n/a')"
  echo "xcode-select        : $(xcode-select -p 2>/dev/null || echo 'n/a')"
  echo
  echo "## Pishi repo"
  echo "git commit          : $(git rev-parse HEAD 2>/dev/null || echo 'not a git repo')"
  echo "git dirty           : $(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo
  echo "## Kernel base"
  echo "path                : $KERNEL"
  echo "sha256              : $(sha "$KERNEL")"
  echo
  echo "## KDK (if present)"
  ls -d /Library/Developer/KDKs/* 2>/dev/null || echo "(no KDKs installed)"
  echo
  echo "## kext_list"
  echo "path                : $KEXT_LIST"
  echo "sha256              : $(sha "$KEXT_LIST")"
  echo "entries             : $(grep -c -- '-b ' "$KEXT_LIST")"
  echo
  echo "## Output kernel collection"
  echo "path                : $KC_OUT"
  echo "sha256              : $(sha "$KC_OUT")"
  echo
  # Read the kexts from the collection itself (not the booted system), so the
  # hashes are of the exact binaries that were linked in, patched ones included.
  # Paths outside /System/Library are marked with '*'. On Apple silicon the
  # system kexts have no binary on disk (it only lives in the stock KCs).
  echo "## Kexts in the collection — id, version, sha256 of binary, source path"
  kmutil inspect -V release --no-header -B "$KC_OUT" | grep $'\t' | sort | while IFS=$'\t' read -r bid ver path _; do
    exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$path/Contents/Info.plist" 2>/dev/null || echo '')"
    if [ -z "$exe" ]; then h="(codeless kext)"
    elif [ -f "$path/Contents/MacOS/$exe" ]; then h="$(sha "$path/Contents/MacOS/$exe")"
    else h="(no binary on disk)"; fi
    case "$path" in /System/Library/*) mark=" " ;; *) mark="*" ;; esac
    printf "%s %-55s %-14s %-64s %s\n" "$mark" "$bid" "$ver" "$h" "$path"
  done
  echo
  echo "## Kexts in kext_list but not in the collection (e.g. DriverKit dexts)"
  comm -23 <(sed -n 's/^ *-b //p' "$KEXT_LIST" | sort -u) \
           <(kmutil inspect -V release --no-header -B "$KC_OUT" | grep $'\t' | cut -f1 | sort -u)
} | tee "$MAN"

echo
echo ">> manifest written: $MAN"
