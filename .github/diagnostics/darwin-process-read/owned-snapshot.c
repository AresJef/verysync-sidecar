#include <libproc.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <unistd.h>

struct sample {
    uint64_t birth_us;
    uint64_t rss_bytes;
    uint64_t user_ns;
    uint64_t system_ns;
};

static mach_timebase_info_data_t timebase;

int prepare_owned_reader(void) {
    return mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0;
}

static uint64_t nanoseconds(uint64_t ticks) {
    return (uint64_t)(((__uint128_t)ticks * timebase.numer) / timebase.denom);
}

/* Test-only: restrict observation to a retained direct child of this process. */
int read_owned_sample(int pid, uint64_t expected_birth_us, struct sample *out) {
    struct proc_taskallinfo value;
    if (pid <= 0 || out == 0 || timebase.denom == 0) {
        return 1;
    }
    int size = (int)sizeof(value);
    if (proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &value, size) != size ||
        value.pbsd.pbi_pid != (uint32_t)pid ||
        value.pbsd.pbi_ppid != (uint32_t)getpid() ||
        value.pbsd.pbi_uid != geteuid()) {
        return 1;
    }
    uint64_t birth = value.pbsd.pbi_start_tvsec * 1000000 + value.pbsd.pbi_start_tvusec;
    if (birth == 0 || (expected_birth_us != 0 && birth != expected_birth_us)) {
        return 2;
    }
    *out = (struct sample){birth, value.ptinfo.pti_resident_size,
                           nanoseconds(value.ptinfo.pti_total_user),
                           nanoseconds(value.ptinfo.pti_total_system)};
    return 0;
}
