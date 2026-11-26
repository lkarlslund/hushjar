#!/usr/bin/env bash
# Builds an Android APK of Hushjar without Gradle: Cargo builds the app as a
# shared library for each ABI, aapt2 links the manifest and icons, and the
# APK is aligned and signed with the SDK's build tools.
#
#   scripts/build-android.sh [--release] [arm64-v8a] [x86_64]
#
# With no ABI it builds both: arm64-v8a for phones, x86_64 for the emulator.
# Writes dist/hushjar-<version>-android-debug.apk, or -android.apk with
# --release. A release is signed with $ANDROID_KEYSTORE (password in
# $ANDROID_KEYSTORE_PASS, key $ANDROID_KEY_ALIAS) when that is set, and with
# the debug key otherwise.
#
# Needs: the Rust targets (rustup target add aarch64-linux-android
# x86_64-linux-android), an Android SDK with a platform and build tools, the
# NDK, and a JDK (javac compiles Slint's small Java helper; keytool makes a
# debug key). ANDROID_HOME and ANDROID_NDK_ROOT pick them; otherwise the
# first SDK of ~/Android/Sdk and /opt/android-sdk is used, with the newest
# NDK found in either.
set -euo pipefail
cd "$(dirname "$0")/.."

min_sdk=28
target_sdk=35
package=io.github.lkarlslund.hushjar

profile=debug
abis=()
for arg in "$@"; do
    case $arg in
        --release) profile=release ;;
        arm64-v8a | x86_64) abis+=("$arg") ;;
        -h | --help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $arg (try --help)" >&2; exit 2 ;;
    esac
done
[ ${#abis[@]} -gt 0 ] || abis=(arm64-v8a x86_64)

newest() { find "$1" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort -V | tail -n1 || true; }

candidates=("${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Android/Sdk" /opt/android-sdk)
sdk=
for dir in "${candidates[@]}"; do
    if [ -n "$dir" ] && [ -d "$dir/platforms" ] && [ -d "$dir/build-tools" ]; then sdk=$dir; break; fi
done
[ -n "$sdk" ] || { echo "No Android SDK found; set ANDROID_HOME" >&2; exit 1; }
ndk=${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-}}
if [ -z "$ndk" ]; then
    for dir in "$sdk" "${candidates[@]}"; do
        ndk_version=$(newest "$dir/ndk")
        if [ -n "$dir" ] && [ -n "$ndk_version" ]; then ndk=$dir/ndk/$ndk_version; break; fi
    done
fi
[ -d "$ndk/toolchains" ] || { echo "No Android NDK found; set ANDROID_NDK_ROOT" >&2; exit 1; }
build_tools=$sdk/build-tools/$(newest "$sdk/build-tools")
android_jar=$sdk/platforms/$(newest "$sdk/platforms")/android.jar
[ -f "$android_jar" ] || { echo "No Android platform found in $sdk/platforms" >&2; exit 1; }
case "$(uname -s)" in
    Linux) host=linux-x86_64 ;;
    Darwin) host=darwin-x86_64 ;;
    *) echo "Build Android on Linux or macOS" >&2; exit 1 ;;
esac
llvm=$ndk/toolchains/llvm/prebuilt/$host/bin
# Slint's Android backend compiles a Java helper against the SDK in its
# build script, and finds the SDK through these.
export ANDROID_HOME=$sdk ANDROID_NDK_ROOT=$ndk

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
IFS=. read -r major minor patch <<<"${version%%-*}"
version_code=$((major * 10000 + minor * 100 + patch))

work=target/android-apk/$profile
rm -rf "$work"
mkdir -p "$work/lib" dist

cargo_flags=()
[ "$profile" = release ] && cargo_flags+=(--release)
for abi in "${abis[@]}"; do
    case $abi in
        arm64-v8a) triple=aarch64-linux-android ;;
        x86_64) triple=x86_64-linux-android ;;
    esac
    env_triple=${triple//-/_}
    upper=${env_triple^^}
    clang=$llvm/$triple$min_sdk-clang
    # ring (through rustls) and Skia compile C and C++ with the NDK's clang.
    export "CC_$env_triple=$clang" "CXX_$env_triple=$clang++" "AR_$env_triple=$llvm/llvm-ar"
    export "CARGO_TARGET_${upper}_LINKER=$clang"
    echo "Building $triple ($profile)"
    cargo rustc -p hushjar --lib --target "$triple" --crate-type cdylib "${cargo_flags[@]}"
    mkdir -p "$work/lib/$abi"
    # The unstripped library stays in target/ for reading crash traces.
    "$llvm/llvm-strip" --strip-all -o "$work/lib/$abi/libhushjar.so" \
        "target/$triple/$profile/libhushjar.so"
done

link_flags=()
[ "$profile" = debug ] && link_flags+=(--debug-mode)
"$build_tools/aapt2" compile --dir packaging/android/res -o "$work/res.zip"
"$build_tools/aapt2" link -o "$work/unaligned.apk" \
    --manifest packaging/android/AndroidManifest.xml -I "$android_jar" \
    --min-sdk-version "$min_sdk" --target-sdk-version "$target_sdk" \
    --version-code "$version_code" --version-name "$version" \
    "${link_flags[@]}" "$work/res.zip"
# Native libraries go in uncompressed so Android can map them in place.
(cd "$work" && zip -q -0 -r unaligned.apk lib)
"$build_tools/zipalign" -f -P 16 4 "$work/unaligned.apk" "$work/aligned.apk"

if [ "$profile" = release ] && [ -n "${ANDROID_KEYSTORE:-}" ]; then
    : "${ANDROID_KEY_ALIAS:?Set ANDROID_KEY_ALIAS to the key in ANDROID_KEYSTORE}"
    keystore=$ANDROID_KEYSTORE
    sign=(--ks-key-alias "$ANDROID_KEY_ALIAS" --ks-pass env:ANDROID_KEYSTORE_PASS)
    out=dist/hushjar-$version-android.apk
else
    keystore=$HOME/.android/debug.keystore
    if [ ! -f "$keystore" ]; then
        mkdir -p "$(dirname "$keystore")"
        keytool -genkeypair -keystore "$keystore" -storepass android -keypass android \
            -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US"
    fi
    sign=(--ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android)
    if [ "$profile" = release ]; then
        echo "ANDROID_KEYSTORE is not set: signing the release with the debug key" >&2
        out=dist/hushjar-$version-android-debugkey.apk
    else
        out=dist/hushjar-$version-android-debug.apk
    fi
fi
"$build_tools/apksigner" sign --ks "$keystore" "${sign[@]}" --out "$out" "$work/aligned.apk"
echo "Wrote $out ($package; install with: adb install -r $out)"
