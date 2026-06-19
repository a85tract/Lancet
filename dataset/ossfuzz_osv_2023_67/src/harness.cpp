/*
 * Standalone harness for mosquitto broker_fuzz_test_config.
 * Writes fuzz data to a temp config file and calls mosquitto_fuzz_main --test-config.
 */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define kMinInputLength 5
#define kMaxInputLength 10000

extern "C" int mosquitto_fuzz_main(int argc, char *argv[]);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char filename[100];
    FILE *fptr;
    if(size < kMinInputLength || size > kMaxInputLength) return 0;
    umask(0077);
    snprintf(filename, sizeof(filename), "/tmp/mosquitto_%d.conf", getpid());
    fptr = fopen(filename, "wb");
    if(!fptr) return 1;
    fwrite(data, 1, size, fptr);
    fclose(fptr);
    char *argv[5];
    argv[0] = strdup("mosquitto");
    argv[1] = strdup("--test-config");
    argv[2] = strdup("-q");
    argv[3] = strdup("-c");
    argv[4] = strdup(filename);
    mosquitto_fuzz_main(5, argv);
    for(int i=0; i<5; i++) free(argv[i]);
    unlink(filename);
    return 0;
}

int main(int argc, char *argv_main[]) {
    if(argc < 2) { fprintf(stderr, "Usage: %s <input>\n", argv_main[0]); return 1; }
    int fd = open(argv_main[1], O_RDONLY);
    if(fd < 0) { perror("open"); return 1; }
    struct stat st; fstat(fd, &st);
    uint8_t *data = (uint8_t*)malloc(st.st_size);
    ssize_t n = read(fd, data, st.st_size);
    close(fd);
    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", n, argv_main[1]);
    LLVMFuzzerTestOneInput(data, (size_t)n);
    fprintf(stderr, "[harness] Done\n");
    free(data);
    return 0;
}
