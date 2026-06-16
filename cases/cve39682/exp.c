#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <err.h>
#include <linux/tls.h>
#include <sys/mman.h>

#define SYSCHK(x) ({              \
	typeof(x) __res = (x);        \
	if (__res == (typeof(x))-1)   \
		err(1, "SYSCHK(" #x ")"); \
	__res;                        \
})

#define PORT 4444

__attribute__((constructor)) static void pin_trace_cpu(void)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(1, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);

	struct sched_param param = {
		.sched_priority = 99,
	};
	(void)sched_setscheduler(0, SCHED_FIFO, &param);
}

void setup_tls(int sock)
{
	struct tls12_crypto_info_aes_ccm_128 crypto = {0};
	crypto.info.version = TLS_1_2_VERSION;
	crypto.info.cipher_type = TLS_CIPHER_AES_CCM_128;
	SYSCHK(setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls")));
	SYSCHK(setsockopt(sock, SOL_TLS, TLS_RX, &crypto, sizeof(crypto)));
}

int main(int argc, char **argv)
{

	char control[1024];
	char buf[4096];

	int listener, conn, client;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)};

	socklen_t len = sizeof(addr);

	setvbuf(stdout, 0, 2, 0);

	listener = SYSCHK(socket(AF_INET, SOCK_STREAM, 0));
	if (listener < 0)
	{
		perror("socket listener");
		exit(1);
	}

	SYSCHK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)));

	SYSCHK(listen(listener, 1));

	client = SYSCHK(socket(AF_INET, SOCK_STREAM, 0));

	SYSCHK(connect(client, (struct sockaddr *)&addr, sizeof(addr)));

	conn = SYSCHK(accept(listener, NULL, 0));

	setup_tls(conn);

	/* MESSAGE 1: Raw TLS 1.2 record for plaintext: 'Hello world' */
	/* Sequence Number: 0 */
	/* Total length: 40 bytes */
	unsigned char tls_record_1[] = {
		0x17, 0x03, 0x03, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x26, 0xa2, 0x33, 0xde, 0x8d, 0x94, 0xf0, 0x29, 0x6c, 0xb1, 0xaf,
		0x6a, 0x75, 0xb2, 0x93, 0xad, 0x45, 0xd5, 0xfd, 0x03, 0x51, 0x57, 0x8f,
		0xf9, 0xcc, 0x3b, 0x42};
	unsigned int tls_record_1_len = sizeof(tls_record_1);

	/* MESSAGE 2: Raw TLS 1.2 record for plaintext: '' */
	/* Sequence Number: 1 */
	/* Total length: 29 bytes */
	unsigned char tls_record_2[] = {
		0x16, 0x03, 0x03, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x3e, 0xf0, 0xfe, 0xee, 0xd9, 0xe2, 0x5d, 0xc7, 0x11, 0x4c, 0xe6,
		0xb4, 0x7e, 0xef, 0x40, 0x2b};
	unsigned int tls_record_2_len = sizeof(tls_record_2);

	/* MESSAGE 3: Raw TLS 1.2 record for plaintext: 'Hello world' */
	/* Sequence Number: 2 */
	/* Total length: 40 bytes */
	unsigned char tls_record_3[] = {
		0x17, 0x03, 0x03, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0xe5, 0x3d, 0x19, 0x3d, 0xca, 0xb8, 0x16, 0xb6, 0xff, 0x79, 0x87,
		0x8e, 0xa1, 0xd0, 0xcd, 0x33, 0xb5, 0x86, 0x2b, 0x17, 0xf1, 0x52, 0x2a,
		0x55, 0x62, 0x65, 0x11};

	unsigned int tls_record_3_len = sizeof(tls_record_3);

	write(client, tls_record_1, sizeof(tls_record_1));

	write(client, tls_record_2, sizeof(tls_record_2));

	int n = read(conn, buf, 0x100);

	write(client, tls_record_3, sizeof(tls_record_3));

	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};

	struct msghdr lmsg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
		.msg_flags = 0,
	};

	n = recvmsg(conn, &lmsg, 0);

	close(conn);

	return 0;
}
