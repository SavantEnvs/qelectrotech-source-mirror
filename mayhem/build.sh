#!/usr/bin/env bash
#
# mayhem/build.sh — QElectroTech: the application (qelectrotech) and a libFuzzer harness over its
# headless command line, both compiled with $SANITIZER_FLAGS + SanitizerCoverage and DWARF 3.
#
# Upstream's CMake build is used as is; nothing upstream is edited:
#   * mayhem/fuzz/project_include.cmake is injected with CMAKE_PROJECT_qelectrotech_INCLUDE and adds
#     the harness targets, linked against upstream's qelectrotech_objects library.
#   * Dependencies are offline: Qt6/KF6/pugixml/SQLite from apt (BUILD_KF=OFF, BUILD_PUGIXML=OFF),
#     SingleApplication from /opt/toolchains/deps, FETCHCONTENT_FULLY_DISCONNECTED=ON, and
#     find_package(Git) disabled so cmake/git_update_submodules.cmake does not run
#     `git submodule update` (network) on configure.
#
# mayhem/lsan_off.cc (LeakSanitizer off, ASan/UBSan on) is linked into every fuzz/standalone binary
# and the CLI, via QET_LSAN_OFF_SRC.
# The upstream test suite (tests/: qttest, catch, modal-quit-regression) is built in a second, clean
# tree with the project's normal flags (Debug, as upstream CI builds it; no sanitizers) for test.sh.
# Outputs: /mayhem/qelectrotech (the CLI, used by test.sh), /mayhem/fuzz_qet_<mode> and
# /mayhem/fuzz_qet_<mode>-standalone (hard links to one harness; the mode comes from argv[0]).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"          # gitignored (mayhem/.gitignore)
mkdir -p "$B"

# SanitizerCoverage on the whole application so libFuzzer/Mayhem see edges in project code.
COV_FLAGS="-fsanitize=fuzzer-no-link"
# Q_ASSERT stays live: Qt6::Core adds QT_NO_DEBUG to every non-Debug configuration, which would turn
# every Q_ASSERT/Q_ASSERT_X (the project's own invariants and Qt's inline container bounds checks) into
# a no-op. QT_FORCE_ASSERTS keeps them compiled in (qassert.h); a failed one is qFatal -> abort.
FLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -DQT_FORCE_ASSERTS"

# Standalone run-once driver, compiled as C so its LLVMFuzzerTestOneInput reference stays unmangled.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

SA_SRC=/opt/toolchains/deps/SingleApplication-3.2.0/src
cmake -S "$SRC" -B "$B" -G Ninja \
  -DCMAKE_BUILD_TYPE=None \
  -DCMAKE_C_FLAGS="$FLAGS" \
  -DCMAKE_CXX_FLAGS="$FLAGS" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DPACKAGE_TESTS=OFF \
  -DBUILD_KF=OFF -DBUILD_PUGIXML=OFF \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_SINGLEAPPLICATION="$SA_SRC" \
  -DCMAKE_DISABLE_FIND_PACKAGE_Git=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Qml=ON \
  -DQET_STANDALONE_MAIN_OBJ="$B/standalone_main.o" \
  -DQET_LSAN_OFF_SRC="$SRC/mayhem/lsan_off.cc" \
  -DCMAKE_PROJECT_qelectrotech_INCLUDE="$SRC/mayhem/fuzz/project_include.cmake"

cmake --build "$B" -j"$MAYHEM_JOBS" --target qelectrotech qet_cli_fuzzer qet_cli_fuzzer-standalone

install -m 0755 "$B/qelectrotech" "$SRC/qelectrotech"
install -m 0755 "$B/qet_cli_fuzzer" "$SRC/qet_cli_fuzzer"
install -m 0755 "$B/qet_cli_fuzzer-standalone" "$SRC/qet_cli_fuzzer-standalone"
for mode in resave qetz recover dxf svg nets elmt qetdb edz; do
  ln -f "$SRC/qet_cli_fuzzer" "$SRC/fuzz_qet_$mode"
  ln -f "$SRC/qet_cli_fuzzer-standalone" "$SRC/fuzz_qet_$mode-standalone"
done

# (b) Upstream's test suite, in its own tree with the project's normal flags: CMAKE_BUILD_TYPE=Debug
# as upstream CI configures it (.github/workflows/linux-build.yml), no sanitizers, no coverage
# instrumentation ($COVERAGE_FLAGS only when asked for), debug info off to keep ~170 links small.
#   * Catch2 v2.13.10 (tests/catch FetchContent) comes from /opt/toolchains/deps (Dockerfile).
#   * Python3 is hidden from CMake, so the run_*_probe.py tests are not registered: each of them
#     compiles and links a probe with ninja in this tree at test time (test.sh must not compile).
#   * Qt Qml stays off, as in the fuzz build, so the scripting (--run) tests are left out by CMake.
T="$SRC/mayhem/build-tests"    # gitignored (mayhem/.gitignore)
cmake -S "$SRC" -B "$T" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS_DEBUG="-O0" -DCMAKE_CXX_FLAGS_DEBUG="-O0" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DPACKAGE_TESTS=ON \
  -DBUILD_KF=OFF -DBUILD_PUGIXML=OFF \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_SINGLEAPPLICATION="$SA_SRC" \
  -DFETCHCONTENT_SOURCE_DIR_CATCH2=/opt/toolchains/deps/Catch2-2.13.10/src \
  -DCMAKE_DISABLE_FIND_PACKAGE_Git=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_Qt6Qml=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_Python3=ON
cmake --build "$T" -j"$MAYHEM_JOBS"
