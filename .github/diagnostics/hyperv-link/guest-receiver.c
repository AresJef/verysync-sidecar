#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

enum { PORT = 47527, SAMPLE_SIZE = 1048576 };
static unsigned char data[SAMPLE_SIZE];

static int reject_socket(int socket_id) {
    int reason = errno;
    close(socket_id);
    errno = reason;
    return -1;
}

static int open_receiver(int family, const char *listen_at) {
    struct sockaddr_in address4 = {0};
    struct sockaddr_in6 address6 = {0};
    address4.sin_family = AF_INET;
    address4.sin_port = htons(PORT);
    address6.sin6_family = AF_INET6;
    address6.sin6_port = htons(PORT);
    int listener = socket(family, SOCK_STREAM, IPPROTO_TCP);
    int parsed = family == AF_INET
        ? inet_pton(family, listen_at, &address4.sin_addr)
        : inet_pton(family, listen_at, &address6.sin6_addr);
    if (listener < 0)
        return -1;
    if (parsed != 1) {
        errno = EINVAL;
        return reject_socket(listener);
    }
    if (family == AF_INET6) {
        int one = 1;
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0)
            return reject_socket(listener);
    }
    struct sockaddr *address = family == AF_INET
        ? (struct sockaddr *)&address4 : (struct sockaddr *)&address6;
    socklen_t size = family == AF_INET ? sizeof(address4) : sizeof(address6);
    if (bind(listener, address, size) < 0 || listen(listener, 1) < 0)
        return reject_socket(listener);
    return listener;
}

static int wait_for_receiver(int family, const char *address) {
    for (int wait_step = 0; wait_step < 80; wait_step++) {
        int opened = open_receiver(family, address);
        if (opened >= 0) {
            printf("RECEIVER_GUEST_BIND family=%d readiness_checks=%d\n",
                   family == AF_INET ? 4 : 6, wait_step + 1);
            return opened;
        }
        if (errno != EADDRNOTAVAIL) {
            fprintf(stderr, "bind %s: %s\n", address, strerror(errno));
            return -1;
        }
        if (wait_step == 0) {
            printf("RECEIVER_GUEST_BIND_PENDING family=%d address_not_yet_bindable=true\n",
                   family == AF_INET ? 4 : 6);
        }
        usleep(100000);
    }
    fprintf(stderr, "bind %s: no usable address within 8 seconds\n", address);
    return -1;
}

static int transfer(int listener, int family, const char *expected) {
    struct sockaddr_storage remote = {0};
    socklen_t size = sizeof(remote);
    int connected = accept(listener, (struct sockaddr *)&remote, &size);
    if (connected < 0 || remote.ss_family != family)
        return -1;
    const void *source = family == AF_INET
        ? (const void *)&((struct sockaddr_in *)&remote)->sin_addr
        : (const void *)&((struct sockaddr_in6 *)&remote)->sin6_addr;
    char remote_ip[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, source, remote_ip, sizeof(remote_ip)) ||
        strcmp(remote_ip, expected) != 0)
        return -1;

    struct timeval timeout = {.tv_sec = 10};
    if (setsockopt(connected, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(connected, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
        return -1;
    size_t count = 0;
    while (count < sizeof(data)) {
        ssize_t n = read(connected, data + count, sizeof(data) - count);
        if (n <= 0)
            return -1;
        count += (size_t)n;
    }
    unsigned char extra;
    if (read(connected, &extra, 1) != 0)
        return -1;
    for (size_t sent = 0; sent < sizeof(data);) {
        ssize_t n = write(connected, data + sent, sizeof(data) - sent);
        if (n <= 0)
            return -1;
        sent += (size_t)n;
    }
    close(connected);
    printf("RECEIVER_GUEST_DATA family=%d source=%s actual_echo_bytes=%zu\n",
           family == AF_INET ? 4 : 6, remote_ip, count);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(115);
    int ipv4 = wait_for_receiver(AF_INET, "192.0.2.2");
    int ipv6 = wait_for_receiver(AF_INET6, "2001:db8:73f:43::2");
    if (ipv4 < 0 || ipv6 < 0) {
        fprintf(stderr, "receive sockets did not become ready\n");
        return 2;
    }
    puts("RECEIVER_GUEST_READY families=4,6");
    if (transfer(ipv4, AF_INET, "192.0.2.1") < 0 ||
        transfer(ipv6, AF_INET6, "2001:db8:73f:43::1") < 0) {
        perror("synthetic receive and echo");
        return 3;
    }
    close(ipv4);
    close(ipv6);
    return 0;
}
