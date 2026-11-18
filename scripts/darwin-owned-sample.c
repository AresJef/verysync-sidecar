#include <libproc.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <unistd.h>

struct owned_sample {
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

/* Diagnostic targets come from the isolated controller's journal. */
int read_owned_sample(int pid, int parent, uint64_t birth_us, struct owned_sample *out) {
    struct proc_taskallinfo process;
    if (pid <= 0 || parent <= 0 || out == NULL || timebase.denom == 0) {
        return 1;
    }
    int size = (int)sizeof(process);
    if (proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &process, size) != size ||
        process.pbsd.pbi_pid != (uint32_t)pid ||
        process.pbsd.pbi_ppid != (uint32_t)parent ||
        process.pbsd.pbi_uid != geteuid()) {
        return 1;
    }
    uint64_t created_us = process.pbsd.pbi_start_tvsec * 1000000 + process.pbsd.pbi_start_tvusec;
    if (created_us == 0 || (birth_us != 0 && created_us != birth_us)) {
        return 2;
    }
    *out = (struct owned_sample){
        created_us,
        process.ptinfo.pti_resident_size,
        nanoseconds(process.ptinfo.pti_total_user),
        nanoseconds(process.ptinfo.pti_total_system),
    };
    return 0;
}
