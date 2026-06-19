/*
 * Harness for OSV-2022-24: null dereference in libssh2
 *
 * The bug is in libssh2's key exchange negotiation. The kex methods list
 * includes extension markers like "ext-info-c" and "kex-strict-c-v00@openssh.com"
 * whose exchange_keys function pointer is NULL. If a malicious server offers
 * only "ext-info-c" as a key exchange algorithm, libssh2 will negotiate it
 * (since its flags=0, no signing/encryption is required from the hostkey).
 * Then _libssh2_kex_exchange() calls session->kex->exchange_keys(), which
 * dereferences the NULL function pointer, causing a crash.
 *
 * The fix in commit b89858b8 disables deprecated algorithms by default,
 * changing the crypto_config.h macros from opt-out (LIBSSH2_NO_*) to opt-in
 * (LIBSSH2_*_ENABLE). This changes the default algorithm sets, but the
 * underlying null-deref through extension negotiation markers remains until
 * a later commit (631e2f82) adds a NULL check for exchange_keys.
 *
 * The fuzzer (ssh2_client_fuzzer.cc) creates a socket pair, sends fuzz data
 * into one end, and runs libssh2_session_handshake on the other end.
 * The PoC sends a valid SSH banner followed by a crafted KEXINIT packet
 * that offers only "ext-info-c" as the kex algorithm.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libssh2.h"

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if(fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if(fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    unsigned char *data = (unsigned char *)malloc(st.st_size);
    if(!data) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t nread = read(fd, data, st.st_size);
    close(fd);
    if(nread != st.st_size) {
        fprintf(stderr, "Short read\n");
        free(data);
        return 1;
    }

    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", nread,
            argv[1]);

    /* Replicate the fuzzer: socketpair, send data, handshake */
    int socket_fds[2] = {-1, -1};
    int rc;
    LIBSSH2_SESSION *session = NULL;
    int handshake_completed = 0;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "[harness] libssh2_init failed (%d)\n", rc);
        free(data);
        return 1;
    }

    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds);
    if(rc != 0) {
        fprintf(stderr, "[harness] socketpair failed\n");
        libssh2_exit();
        free(data);
        return 1;
    }

    ssize_t written = send(socket_fds[1], data, nread, 0);
    if(written != nread) {
        fprintf(stderr, "[harness] send() of %zd bytes returned %zd (%s)\n",
                nread, written, strerror(errno));
        goto cleanup;
    }

    rc = shutdown(socket_fds[1], SHUT_WR);
    if(rc) {
        fprintf(stderr, "[harness] shutdown failed (%d)\n", rc);
        goto cleanup;
    }

    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "[harness] libssh2_session_init failed\n");
        goto cleanup;
    }

    libssh2_session_set_blocking(session, 1);

    fprintf(stderr, "[harness] Starting handshake...\n");
    rc = libssh2_session_handshake(session, socket_fds[0]);
    fprintf(stderr, "[harness] Handshake returned %d\n", rc);

    if(rc == 0) {
        handshake_completed = 1;
    }

cleanup:
    if(session) {
        if(handshake_completed) {
            libssh2_session_disconnect(session,
                                       "Normal Shutdown");
        }
        libssh2_session_free(session);
    }

    libssh2_exit();

    if(socket_fds[0] >= 0)
        close(socket_fds[0]);
    if(socket_fds[1] >= 0)
        close(socket_fds[1]);

    fprintf(stderr, "[harness] Done\n");
    free(data);
    return 0;
}
