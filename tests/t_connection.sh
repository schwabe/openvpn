#!/bin/sh
set -eu

# by changing this to 1 we can force automated builds to fail
# that are expected to have all the prerequisites
TCLIENT_SKIP_RC="${TCLIENT_SKIP_RC:-77}"
export OPENVPN_BINARY="$(readlink -f ${top_builddir}/src/openvpn/openvpn)"
export WORK_DIR="$(readlink -f ${top_srcdir}/sample/)"

if ! which python3 > /dev/null; then
    echo "$0: Python3 not found, skipping connection tests."
    exit "${TCLIENT_SKIP_RC}"
fi

if ! python3 -m pytest --version 2> /dev/null; then
    echo "$0: Pytest not found, skipping connection tests."
    exit "${TCLIENT_SKIP_RC}"
fi

# TODO - possible improvements
# - Create and run from venv?
# - Integrate as separate target through Makefile.am ?
# - Use configure to create test config file ?
(cd "${top_srcdir}/tests/connection_tests" && python3 -m pytest -v)
