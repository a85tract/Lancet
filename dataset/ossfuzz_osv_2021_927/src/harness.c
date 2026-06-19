/*
 * Harness for OSV-2021-927 (dnsmasq heap-buffer-overflow WRITE in dhcp_reply)
 *
 * Reads a PoC file and feeds it through the DHCP packet processing
 * path (same as fuzz_dhcp FuzzDhcp target).
 */
#include "dnsmasq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/uio.h>


#define GB_SIZE 100
void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

void gb_init() {
    pointer_idx = 0;
    for (int i = 0; i < GB_SIZE; i++) pointer_arr[i] = NULL;
}
void gb_cleanup() {
    for (int i = 0; i < GB_SIZE; i++)
        if (pointer_arr[i]) free(pointer_arr[i]);
}
char *gb_alloc_data(size_t len) {
    char *p = calloc(1, len);
    if (p && pointer_idx < GB_SIZE) pointer_arr[pointer_idx++] = p;
    return p;
}
void fuzz_blockdata_cleanup(void) {}

const uint8_t *syscall_data = NULL;
size_t syscall_size = 0;

ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    struct iovec *target = msg->msg_iov;
    if (syscall_size > 1) {
        char r = *syscall_data; syscall_data++; syscall_size--;
        if (r == 12) return -1;
    }
    if (msg->msg_control) {
        for (int j = 0; j < CMSG_SPACE(sizeof(struct in_pktinfo)); j++) {
            ((char *)msg->msg_control)[j] = (syscall_size > 0) ?
                (syscall_data++, syscall_size--, *(syscall_data-1)) : 'A';
        }
    }
    int i = 0;
    for (; i < (int)target->iov_len; i++) {
        ((char *)target->iov_base)[i] = (syscall_size > 0) ?
            (syscall_data++, syscall_size--, *(syscall_data-1)) : 'A';
    }
    if (msg->msg_namelen > 0) memset(msg->msg_name, 0, msg->msg_namelen);
    return i;
}

int fuzz_ioctl(int fd, unsigned long request, void *arg) {
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <poc>\n", argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    gb_init();

    daemon = (struct daemon *)gb_alloc_data(sizeof(struct daemon));
    if (!daemon) { gb_cleanup(); free(buf); return 1; }
    daemon->namebuff = gb_alloc_data(MAXDNAME);
    daemon->addrbuff = gb_alloc_data(200);
    daemon->dhcp_buff = gb_alloc_data(DHCP_BUFF_SZ);
    daemon->dhcp_buff2 = gb_alloc_data(DHCP_BUFF_SZ);
    daemon->dhcp_buff3 = gb_alloc_data(DHCP_BUFF_SZ);

    cache_init();
    blockdata_init();

    /* DHCP packet path */
    struct iovec dhpa;
    char *content = malloc(sizeof(struct dhcp_packet));
    if (content) {
        dhpa.iov_base = content;
        dhpa.iov_len = sizeof(struct dhcp_packet);
        daemon->dhcp_packet = dhpa;

        syscall_data = buf;
        syscall_size = sz;

        time_t now = 0;
        int pxe_fd = 0;
        dhcp_packet(now, pxe_fd);

        free(daemon->dhcp_packet.iov_base);
    }

    gb_cleanup();
    free(buf);
    return 0;
}
