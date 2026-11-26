#define _DARWIN_C_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
static const char architecture[] = "x86_64";
#elif defined(__arm64__)
static const char architecture[] = "arm64";
#else
#error This probe requires a supported native macOS architecture
#endif

static size_t page_bytes;
static void *held;
static size_t held_bytes;
static char page_flags[65536];

static void die(const char *operation) {
    perror(operation);
    exit(2);
}

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
        die("clock_gettime");
    }
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static void sleep_ms(long ms) {
    struct timespec left = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&left, &left) != 0) {
        if (errno != EINTR) {
            die("nanosleep");
        }
    }
}

static void snapshot(void) {
    mach_task_basic_info_data_t basic = {0};
    task_vm_info_data_t vm = {0};
    mach_msg_type_number_t basic_count = MACH_TASK_BASIC_INFO_COUNT;
    mach_msg_type_number_t vm_count = TASK_VM_INFO_COUNT;
    uint64_t begin = now_ns();
    kern_return_t basic_status = task_info(
        mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&basic, &basic_count);
    kern_return_t vm_status =
        task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm, &vm_count);
    uint64_t end = now_ns();
    printf("{\"event\":\"snapshot\",\"begin_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64
           ",\"basic_status\":%d,\"basic_count\":%u,\"basic_rss_bytes\":%" PRIu64
           ",\"basic_peak_bytes\":%" PRIu64 ",\"vm_status\":%d,\"vm_count\":%u"
           ",\"vm_rss_bytes\":%" PRIu64 ",\"vm_peak_bytes\":%" PRIu64 "}\n",
           begin, end, basic_status, basic_count, (uint64_t)basic.resident_size,
           (uint64_t)basic.resident_size_max, vm_status, vm_count,
           (uint64_t)vm.resident_size, (uint64_t)vm.resident_size_peak);
}

static void allocate_and_touch(size_t bytes) {
    held = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (held == MAP_FAILED) {
        die("mmap");
    }
    held_bytes = bytes;
    volatile unsigned char *pages = held;
    for (size_t offset = 0; offset < bytes; offset += page_bytes) {
        pages[offset] = (unsigned char)(1 + (offset / page_bytes) % 251);
    }
}

static size_t mapped_resident_bytes(void) {
    if (held_bytes == 0) {
        return 0;
    }
    size_t page_count = held_bytes / page_bytes;
    if (page_count > sizeof(page_flags) || mincore(held, held_bytes, page_flags) != 0) {
        die("mincore");
    }
    size_t resident = 0;
    for (size_t page = 0; page < page_count; ++page) {
        if ((page_flags[page] & MINCORE_INCORE) != 0) {
            resident += page_bytes;
        }
    }
    return resident;
}

static void unmap(void) {
    if (held_bytes && munmap(held, held_bytes) != 0) {
        die("munmap");
    }
    held = NULL;
    held_bytes = 0;
}

static void observe_mapping(size_t bytes, int transient) {
    if (held_bytes != 0 || bytes % page_bytes != 0) {
        fputs("unexpected mapping state or page alignment\n", stderr);
        exit(2);
    }
    if (transient) {
        sleep_ms(150);
    }
    uint64_t begin = now_ns();
    if (bytes != 0) {
        allocate_and_touch(bytes);
    }
    uint64_t touched = now_ns();
    if (transient) {
        sleep_ms(200);
    }
    size_t resident = mapped_resident_bytes();
    uint64_t verified = now_ns();
    uint64_t release_begin = 0;
    uint64_t released = 0;
    if (transient) {
        release_begin = now_ns();
        unmap();
        released = now_ns();
    }
    printf("{\"event\":\"%s\",\"mapping_begin_ns\":%" PRIu64
           ",\"touch_done_ns\":%" PRIu64 ",\"mincore_done_ns\":%" PRIu64
           ",\"unmap_begin_ns\":%" PRIu64 ",\"unmapped_ns\":%" PRIu64
           ",\"requested_bytes\":%zu,\"mapped_resident_bytes\":%zu}\n",
           transient ? "pulse" : "hold", begin, touched, verified, release_begin,
           released, bytes, resident);
}

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        die("sysconf page size");
    }
    page_bytes = (size_t)page;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"event\":\"hello\",\"pid\":%ld,\"architecture\":\"%s\""
           ",\"page_bytes\":%zu,\"proc_task_flavor\":%d,\"proc_task_size\":%zu"
           ",\"proc_rss_offset\":%zu}\n",
           (long)getpid(), architecture, page_bytes, PROC_PIDTASKINFO,
           sizeof(struct proc_taskinfo), offsetof(struct proc_taskinfo, pti_resident_size));
    char line[64];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char command[16];
        unsigned mib;
        if (strcmp(line, "snapshot\n") == 0) {
            snapshot();
        } else if (strcmp(line, "release\n") == 0 && held_bytes != 0) {
            uint64_t begin = now_ns();
            unmap();
            printf("{\"event\":\"release\",\"unmap_begin_ns\":%" PRIu64
                   ",\"unmapped_ns\":%" PRIu64 "}\n", begin, now_ns());
        } else if (strcmp(line, "stop\n") == 0) {
            unmap();
            puts("{\"event\":\"stop\"}");
            return 0;
        } else if (sscanf(line, "%15s %u", command, &mib) == 2 && mib <= 128 &&
                   (strcmp(command, "pulse") == 0 || strcmp(command, "hold") == 0)) {
            observe_mapping((size_t)mib * 1024 * 1024, strcmp(command, "pulse") == 0);
        } else {
            fputs("invalid probe command\n", stderr);
            return 2;
        }
    }
    unmap();
    return 2;
}
