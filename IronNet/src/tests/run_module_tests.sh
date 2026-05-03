#!/bin/bash
#
# IronNet Module Test Runner
# Runs all module tests and reports results.
#
# Usage:
#   cd IronNet/build
#   ../src/tests/run_module_tests.sh
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-.}"
TEST_DIR="$BUILD_DIR/tests"

PASSED=0
FAILED=0
TOTAL=0
FAILED_TESTS=""

echo "=== IronNet Module Test Runner ==="
echo ""

for test_bin in "$TEST_DIR"/test_*_module; do
    if [ ! -x "$test_bin" ]; then
        continue
    fi

    TOTAL=$((TOTAL + 1))
    test_name=$(basename "$test_bin")

    echo "────────────────────────────────────────────────────────────"
    echo "Running: $test_name"
    echo "────────────────────────────────────────────────────────────"
    echo ""

    "$test_bin" 2>/dev/null
    rc=$?

    echo ""
    if [ $rc -eq 0 ]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_TESTS="$FAILED_TESTS  $test_name\n"
    fi
done

echo "════════════════════════════════════════════════════════════════"
echo "Module Test Results: $PASSED passed, $FAILED failed, $TOTAL total"
if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    echo -e "$FAILED_TESTS"
fi
echo "════════════════════════════════════════════════════════════════"

exit $FAILED
