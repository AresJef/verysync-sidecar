#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <unistd.h>

struct peak_receipt {
    uint64_t birth_us;
    uint64_t basic_rss_bytes;
    uint64_t basic_peak_bytes;
    uint64_t vm_rss_bytes;
    uint64_t vm_peak_bytes;
    uint32_t basic_count;
    uint32_t vm_count;
    int32_t acquire_status;
    int32_t basic_status;
    int32_t vm_status;
    int32_t deallocate_status;
    int32_t identity_errno;
};

static uint64_t matching_birth(int pid, int parent, uint64_t birth, int *error) {
    struct proc_bsdinfo identity;
    const int size = (int)sizeof(identity);
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &identity, size) != size) {
        *error = errno ? errno : EIO;
        return 0;
    }
    if (identity.pbi_pid != (uint32_t)pid || identity.pbi_ppid != (uint32_t)parent ||
            identity.pbi_uid != geteuid()) {
        *error = EPERM;
        return 0;
    }
    uint64_t actual = identity.pbi_start_tvsec * UINT64_C(1000000) + identity.pbi_start_tvusec;
    if (actual == 0 || (birth && birth != actual)) {
        *error = ESRCH;
        return 0;
    }
    return actual;
}

/* This measurement uses only the name port of a known, owned fixture process. */
int read_owned_peak(int pid, int parent, uint64_t birth, struct peak_receipt *out) {
    if (out == NULL || pid <= 0 || parent <= 0 || birth == 0) {
        return EINVAL;
    }
    *out = (struct peak_receipt){.acquire_status = -1, .basic_status = -1,
        .vm_status = -1, .deallocate_status = -1};
    int identity_error = 0;
    out->birth_us = matching_birth(pid, parent, birth, &identity_error);
    if (out->birth_us == 0) {
        return out->identity_errno = identity_error;
    }

    mach_port_name_t port = MACH_PORT_NULL;
    out->acquire_status = task_name_for_pid(mach_task_self(), pid, &port);
    if (out->acquire_status == KERN_SUCCESS && MACH_PORT_VALID(port)) {
        mach_task_basic_info_data_t basic = {0};
        task_vm_info_data_t vm = {0};
        mach_msg_type_number_t basic_count = MACH_TASK_BASIC_INFO_COUNT;
        mach_msg_type_number_t vm_count = TASK_VM_INFO_COUNT;
        out->basic_status = task_info(port, MACH_TASK_BASIC_INFO, (task_info_t)&basic, &basic_count);
        out->vm_status = task_info(port, TASK_VM_INFO, (task_info_t)&vm, &vm_count);
        out->deallocate_status = mach_port_deallocate(mach_task_self(), port);
        out->basic_count = basic_count;
        out->vm_count = vm_count;
        out->basic_rss_bytes = basic.resident_size;
        out->basic_peak_bytes = basic.resident_size_max;
        out->vm_rss_bytes = vm.resident_size;
        out->vm_peak_bytes = vm.resident_size_peak;
    }
    if (!matching_birth(pid, parent, birth, &identity_error)) {
        return out->identity_errno = identity_error;
    }
    return 0;
}
