#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT/build"
ARCHIVE="$BUILD_DIR/VESPER-Build-49.xcarchive"
IPA="$BUILD_DIR/VESPER-Build-49-unsigned.ipa"
WALTER_IPA="$BUILD_DIR/WALTER-X-CHEAT-unsigned.ipa"
WALTER_V2_IPA="$BUILD_DIR/WALTER-X-CHEAT-V2.ipa"
echo "Building repository revision: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo 'local')"

export M3SB_PACKAGE_TOKEN="${M3SB_PACKAGE_TOKEN:-S12mtcUb8r}"
export M3SB_HMAC_SECRET="${M3SB_HMAC_SECRET:-faf96321eed09a7d9986b033624d63c5956c8eef5d3f323cb7e5beaa7f06e273}"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
command -v xcodebuild >/dev/null || { echo 'xcodebuild is required on macOS' >&2; exit 127; }
python3 "$ROOT/generate_embedded_localizations.py"

xcodebuild \
  -project "$ROOT/ThreeOneOSFive.xcodeproj" \
  -scheme 3105 \
  -configuration Release \
  -sdk iphoneos \
  -archivePath "$ARCHIVE" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY='' \
  archive

APP="$ARCHIVE/Products/Applications/VESPER.app"
test -d "$APP"
# Remote patches must never be embedded in the signed app. Remove packages
# from every possible Xcode resource layout, not only from the app root.
find "$APP" -type f -name '*.3105' -print -delete
if find "$APP" -type f -name '*.3105' -print -quit | grep -q .; then
  echo "Error: a local .3105 patch remains inside the app bundle." >&2
  exit 1
fi
echo "Verified no bundled local patch resources; patches are loaded only from VesperDash online."

/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable @rybkx" "$APP/Info.plist" || true
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName WALTER X CHEAT" "$APP/Info.plist" || true
/usr/libexec/PlistBuddy -c "Set :CFBundleName WALTER X CHEAT" "$APP/Info.plist" || true
/usr/libexec/PlistBuddy -c "Set :CFBundlePackageType APPL" "$APP/Info.plist" || true
python3 - "$APP/Info.plist" <<'PY'
import base64
import os
import plistlib
import sys

path = sys.argv[1]
values = {
    "M3SB_PACKAGE_TOKEN_OBFUSCATED": os.environ["M3SB_PACKAGE_TOKEN"],
    "M3SB_HMAC_SECRET_OBFUSCATED": os.environ["M3SB_HMAC_SECRET"],
}
with open(path, "rb") as stream:
    info = plistlib.load(stream)
info.pop("M3SB_PACKAGE_TOKEN", None)
info.pop("M3SB_HMAC_SECRET", None)
for key, value in values.items():
    raw = value.encode("utf-8")
    obfuscated = bytes(byte ^ 0x5A for byte in raw)
    info[key] = base64.b64encode(obfuscated).decode("ascii")
with open(path, "wb") as stream:
    plistlib.dump(info, stream, fmt=plistlib.FMT_XML, sort_keys=False)
print("Embedded obfuscated M3SB configuration in the app bundle.")
PY

test -f "$APP/@rybkx"
# Lean executable without 400 MiB zero-padding so on-device signers (eSign/KSign/Feather)
# sign and install in 1 second instead of timing out on local OTA loopback.
python3 "$ROOT/embed_app_resources.py" "$APP"
python3 "$ROOT/embed_app_resources.py" --strip-audio "$APP"
mkdir -p "$BUILD_DIR/Payload"
cp -R "$APP" "$BUILD_DIR/Payload/"
(
  cd "$BUILD_DIR"
  /usr/bin/zip -9qry "$IPA" Payload
  cp -f "$IPA" "$WALTER_IPA"
  cp -f "$IPA" "$WALTER_V2_IPA"
  rm -rf Payload
)
ls -lh "$IPA" "$WALTER_IPA" "$WALTER_V2_IPA"
echo "$WALTER_V2_IPA"
