/* Entropy control for the disposable offline minimum-kernel guest. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/random.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct seed_input {
    int entropy_bits;
    int byte_count;
    unsigned char bytes[64];
};

_Static_assert(offsetof(struct seed_input, bytes) ==
               offsetof(struct rand_pool_info, buf),
               "kernel RNG ioctl layout changed");

static int seed_guest(int random_fd)
{
    char command_line[512];
    FILE *source = fopen("/proc/cmdline", "r");
    if (source == NULL)
        return 1;
    int allowed = fgets(command_line, sizeof(command_line), source) != NULL &&
                  strstr(command_line, " vs_minimum_entropy=seeded ") != NULL;
    fclose(source);
    if (!allowed || geteuid() != 0)
        return 1;

    struct seed_input seed = {512, 64, {0}};
    if (fread(seed.bytes, 1, sizeof(seed.bytes), stdin) != sizeof(seed.bytes) ||
        fgetc(stdin) != EOF || ferror(stdin))
        return 1;
    if (ioctl(random_fd, RNDADDENTROPY, &seed) < 0)
        return 1;
    printf("VS_MINIMUM_ENTROPY_CREDIT_OK bits=%d\n", seed.entropy_bits);
    return 0;
}

int main(int argc, char **argv)
{
#if defined(__powerpc64__)
    if (argc == 2 && strcmp(argv[1], "power9") == 0) {
        unsigned long result;
        const unsigned long value = 256;
        __asm__ volatile("cnttzd %0,%1" : "=r"(result) : "r"(value));
        if (result != 8) {
            return 1;
        }
        printf("VS_PPC64LE_ISA30 cnttzd_result=%lu\n", result);
        return 0;
    }
#endif
    if (argc != 2)
        return 1;
    int random_fd = open("/dev/random", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (random_fd < 0)
        return 1;
    if (strcmp(argv[1], "seed") == 0) {
        int status = seed_guest(random_fd);
        close(random_fd);
        return status;
    }

    int entropy_bits = 0;
    struct pollfd descriptor = {random_fd, POLLIN, 0};
    if (ioctl(random_fd, RNDGETENTCNT, &entropy_bits) < 0 ||
        poll(&descriptor, 1, 0) < 0 || (descriptor.revents & ~POLLIN) != 0) {
        close(random_fd);
        return 1;
    }
    close(random_fd);
    printf("VS_MINIMUM_ENTROPY phase=%s bits=%d readable=%d\n",
           argv[1], entropy_bits, (descriptor.revents & POLLIN) != 0);
    return 0;
}
