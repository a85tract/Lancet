/*
 * Harness for OSV-2021-925 (dnsmasq stack-buffer-overflow READ)
 *
 * Vulnerability in is_same_net6() called via dhcp6_maybe_relay()
 * This harness reads a PoC binary file and feeds it through the
 * DHCPv6 packet processing path (same as fuzz_dhcp6).
 *
 * File format: raw bytes consumed by init_daemon then used as
 * DHCPv6 packet data fed via mock recvmsg.
 */
#include "dnsmasq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/uio.h>


/* Minimal garbage collector */
#define GB_SIZE 100
void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

void gb_init() {
    pointer_idx = 0;
    for (int i = 0; i < GB_SIZE; i++)
        pointer_arr[i] = NULL;
}

void gb_cleanup() {
    for (int i = 0; i < GB_SIZE; i++) {
        if (pointer_arr[i] != NULL)
            free(pointer_arr[i]);
    }
}

char *gb_alloc_data(size_t len) {
    char *ptr = calloc(1, len);
    if (ptr && pointer_idx < GB_SIZE)
        pointer_arr[pointer_idx++] = (void *)ptr;
    return ptr;
}

void fuzz_blockdata_cleanup(void) {}

/* Syscall data for mock recvmsg */
const uint8_t *syscall_data = NULL;
size_t syscall_size = 0;

ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    struct iovec *target = msg->msg_iov;
    if (syscall_size > 1) {
        char r = *syscall_data;
        syscall_data += 1;
        syscall_size -= 1;
        if (r == 12) return -1;
    }
    int j = 0;
    if (msg->msg_control != NULL) {
        for (; j < CMSG_SPACE(sizeof(struct in_pktinfo)); j++) {
            if (syscall_size > 0 && syscall_data != NULL) {
                ((char *)msg->msg_control)[j] = *syscall_data;
                syscall_data += 1;
                syscall_size -= 1;
            } else {
                ((char *)msg->msg_control)[j] = 'A';
            }
        }
    }
    int i = 0;
    for (; i < (int)target->iov_len; i++) {
        if (syscall_size > 0 && syscall_data != NULL) {
            ((char *)target->iov_base)[i] = *syscall_data;
            syscall_data += 1;
            syscall_size -= 1;
        } else {
            ((char *)target->iov_base)[i] = 'A';
        }
    }
    if (msg->msg_namelen > 0)
        memset(msg->msg_name, 0, msg->msg_namelen);
    return i;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <poc_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t total_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc(total_size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, total_size, f);
    fclose(f);

    gb_init();

    const uint8_t *data = buf;
    size_t size = total_size;

    /* Minimal daemon setup */
    daemon = (struct daemon *)gb_alloc_data(sizeof(struct daemon));
    if (!daemon) { gb_cleanup(); free(buf); return 1; }

    daemon->namebuff = gb_alloc_data(MAXDNAME);
    daemon->addrbuff = gb_alloc_data(200);
    daemon->dhcp_buff = gb_alloc_data(DHCP_BUFF_SZ);
    daemon->dhcp_buff2 = gb_alloc_data(DHCP_BUFF_SZ);
    daemon->dhcp_buff3 = gb_alloc_data(DHCP_BUFF_SZ);
    daemon->doing_dhcp6 = 1;

    cache_init();
    blockdata_init();

    /* Set up DHCPv6 packet buffer and feed data via mock recvmsg */
    struct iovec dhpa;
    char *content = malloc(300);
    if (content) {
        dhpa.iov_base = content;
        dhpa.iov_len = 300;
        daemon->dhcp_packet = dhpa;

        syscall_data = data;
        syscall_size = size;

        time_t now = 0;
        dhcp6_packet(now);

        free(content);
    }

    gb_cleanup();
    free(buf);
    return 0;
}
