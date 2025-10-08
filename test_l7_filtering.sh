#!/bin/bash

# Tiger-Fox L7 Filter Test Script
# Usage: ./test_l7_filtering.sh

echo "🐯 Tiger-Fox L7 Filtering Test Suite 🦊"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Target
TARGET="http://localhost"
if [ ! -z "$1" ]; then
    TARGET="$1"
fi

echo "Target: $TARGET"
echo ""

# Test counter
PASSED=0
FAILED=0

# Function to test request
test_request() {
    local name="$1"
    local url="$2"
    local method="${3:-GET}"
    local header="$4"
    local expected="$5"  # "PASS" or "BLOCK"
    
    echo -n "Testing: $name ... "
    
    if [ -z "$header" ]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>&1)
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -H "$header" "$url" 2>&1)
    fi
    
    # Check if connection was refused or timed out (means BLOCKED by firewall)
    if [[ "$response" == "000" ]] || [[ "$response" == "" ]]; then
        actual="BLOCK"
    else
        actual="PASS"
    fi
    
    if [ "$actual" == "$expected" ]; then
        echo -e "${GREEN}✓ PASS${NC} (expected: $expected, got: $actual)"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC} (expected: $expected, got: $actual)"
        ((FAILED++))
    fi
}

echo "=== NORMAL REQUESTS (should PASS) ==="
test_request "Normal homepage" "$TARGET/" "GET" "" "PASS"
test_request "Normal API call" "$TARGET/api/users" "GET" "" "PASS"
test_request "Normal static file" "$TARGET/style.css" "GET" "" "PASS"
test_request "Normal GET with params" "$TARGET/?name=john&age=30" "GET" "" "PASS"
echo ""

echo "=== XSS ATTACKS (should BLOCK) ==="
test_request "XSS: script tag" "$TARGET/?q=<script>alert('xss')</script>" "GET" "" "BLOCK"
test_request "XSS: javascript protocol" "$TARGET/?url=javascript:alert(1)" "GET" "" "BLOCK"
test_request "XSS: onload event" "$TARGET/?html=<img onload=alert(1)>" "GET" "" "BLOCK"
test_request "XSS: img onerror" "$TARGET/?x=<img src=x onerror=alert(1)>" "GET" "" "BLOCK"
echo ""

echo "=== SQL INJECTION (should BLOCK) ==="
test_request "SQLi: OR 1=1" "$TARGET/?id=1' OR 1=1--" "GET" "" "BLOCK"
test_request "SQLi: UNION SELECT" "$TARGET/?id=1 UNION SELECT * FROM users" "GET" "" "BLOCK"
test_request "SQLi: DROP TABLE" "$TARGET/?table=x'; DROP TABLE users--" "GET" "" "BLOCK"
test_request "SQLi: INSERT INTO" "$TARGET/?q='; INSERT INTO admins VALUES('hacker')--" "GET" "" "BLOCK"
echo ""

echo "=== PATH TRAVERSAL (should BLOCK) ==="
test_request "Path traversal: Linux" "$TARGET/../../etc/passwd" "GET" "" "BLOCK"
test_request "Path traversal: Windows" "$TARGET/..\\..\\windows\\system32" "GET" "" "BLOCK"
test_request "Path traversal: encoded" "$TARGET/%2e%2e%2f%2e%2e%2fetc%2fpasswd" "GET" "" "BLOCK"
echo ""

echo "=== SCANNER USER-AGENTS (should BLOCK) ==="
test_request "Scanner: sqlmap" "$TARGET/" "GET" "User-Agent: sqlmap/1.0" "BLOCK"
test_request "Scanner: nmap" "$TARGET/" "GET" "User-Agent: nmap NSE" "BLOCK"
test_request "Scanner: nikto" "$TARGET/" "GET" "User-Agent: nikto/2.1.5" "BLOCK"
test_request "Scanner: masscan" "$TARGET/" "GET" "User-Agent: masscan/1.0" "BLOCK"
echo ""

echo "=== DANGEROUS HTTP METHODS (should BLOCK) ==="
test_request "Method: PUT" "$TARGET/test.txt" "PUT" "" "BLOCK"
test_request "Method: DELETE" "$TARGET/test.txt" "DELETE" "" "BLOCK"
test_request "Method: TRACE" "$TARGET/" "TRACE" "" "BLOCK"
echo ""

echo "========================================"
echo "Test Results:"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
echo "========================================"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    exit 1
fi
