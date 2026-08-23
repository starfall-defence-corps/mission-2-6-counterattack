#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$ROOT_DIR/molecule/default/tests"

GREEN='\033[32m'
RED='\033[31m'
CYAN='\033[36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

echo ""
echo -e "  ${CYAN}${BOLD}=============================================="
echo -e "  ARIA — Automated Review & Intelligence Analyst"
echo -e "  Mission 2.6: Counterattack"
echo -e "  ==============================================${RESET}"

cd "$ROOT_DIR"

if [ -f "$ROOT_DIR/venv/bin/activate" ]; then
    source "$ROOT_DIR/venv/bin/activate"
fi

# Run the phased verification. conftest.py renders the ARIA report to stderr;
# discard pytest's stdout and its stderr noise, keeping only our ARIA lines.
ARIA_COLOR=1 python3 -m pytest "$TEST_DIR" -p no:cacheprovider --tb=no --no-header -q 2>&1 1>/dev/null \
    | grep -vE '^(assert |FAILED| *\+  where|  *\+  |[0-9]+ (passed|failed|skipped))' || true
EXIT_CODE=${PIPESTATUS[0]}

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}=============================================="
    echo -e "  ARIA: All objectives verified."
    echo -e "  Mission 2.6 status: COMPLETE"
    echo -e ""
    echo -e "  Cadet, the fleet is yours again. Every implant"
    echo -e "  is gone, the credential is rotated, the operator's"
    echo -e "  channel is cut — and the web service never went"
    echo -e "  dark while you did it. Textbook incident response."
    echo -e "  The Starfall Defence Corps salutes you."
    echo -e "  ==============================================${RESET}"
else
    echo -e "  ${RED}${BOLD}=============================================="
    echo -e "  ARIA: Deficiencies detected."
    echo -e "  The intruder still has a foothold. Review the"
    echo -e "  findings above and reinforce your response."
    echo -e ""
    echo -e "  If every check was skipped, the range is not armed —"
    echo -e "  run 'make reset', then 'make test' again."
    echo -e "  ==============================================${RESET}"
fi

echo ""
exit $EXIT_CODE
