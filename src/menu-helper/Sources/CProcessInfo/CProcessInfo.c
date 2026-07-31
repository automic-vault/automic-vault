#include "CProcessInfo.h"

#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

bool av_peer_pid(int fd, pid_t *pid_out) {
    socklen_t len = sizeof(*pid_out);
    return getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, pid_out, &len) == 0;
}

bool av_process_identity(pid_t pid, AVProcessIdentity *identity_out) {
    struct kinfo_proc info;
    size_t len = sizeof(info);
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &len, NULL, 0) != 0 || len == 0) {
        return false;
    }

    memset(identity_out, 0, sizeof(*identity_out));
    identity_out->pid = pid;
    identity_out->ppid = info.kp_eproc.e_ppid;
    identity_out->sid = getsid(pid);
    identity_out->start_usec =
        ((uint64_t)info.kp_proc.p_starttime.tv_sec * 1000000ULL) +
        (uint64_t)info.kp_proc.p_starttime.tv_usec;
    identity_out->euid = info.kp_eproc.e_ucred.cr_uid;

    mach_port_name_t task = MACH_PORT_NULL;
    if (task_name_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS) {
        audit_token_t token = {0};
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) == KERN_SUCCESS) {
            identity_out->pidversion = audit_token_to_pidversion(token);
            identity_out->euid = audit_token_to_euid(token);
            identity_out->audit_session_id = audit_token_to_asid(token);
        }
        mach_port_deallocate(mach_task_self(), task);
    }
    proc_pidpath(pid, identity_out->path, sizeof(identity_out->path));
    return true;
}

bool av_process_arguments(pid_t pid, char *out, size_t out_len) {
    if (out_len == 0) {
        return false;
    }
    out[0] = '\0';

    char buffer[8192];
    size_t len = sizeof(buffer);
    int mib[] = { CTL_KERN, KERN_PROCARGS2, pid };
    if (sysctl(mib, 3, buffer, &len, NULL, 0) != 0 || len <= sizeof(int)) {
        return false;
    }

    int argc = 0;
    memcpy(&argc, buffer, sizeof(argc));
    if (argc <= 0) {
        return false;
    }

    char *cursor = buffer + sizeof(argc);
    char *end = buffer + len;
    while (cursor < end && *cursor != '\0') cursor++;
    while (cursor < end && *cursor == '\0') cursor++;

    size_t written = 0;
    for (int i = 0; i < argc; i++) {
        if (cursor >= end) {
            return false;
        }
        size_t arg_len = strnlen(cursor, (size_t)(end - cursor));
        if (cursor + arg_len >= end) {
            return false;
        }
        if (memchr(cursor, '\n', arg_len) != NULL) {
            return false;
        }
        size_t required = arg_len + (i > 0 ? 1 : 0);
        if (required > out_len - written - 1) {
            return false;
        }
        if (i > 0) {
            out[written++] = '\n';
        }
        memcpy(out + written, cursor, arg_len);
        written += arg_len;
        cursor += arg_len + 1;
    }
    out[written] = '\0';
    return written > 0;
}

bool av_process_environment_value(pid_t pid, const char *key, char *out, size_t out_len) {
    if (key == NULL || key[0] == '\0' || strchr(key, '=') != NULL || out_len == 0) {
        return false;
    }
    out[0] = '\0';

    int argmax = 0;
    size_t argmax_len = sizeof(argmax);
    int argmax_mib[] = { CTL_KERN, KERN_ARGMAX };
    if (sysctl(argmax_mib, 2, &argmax, &argmax_len, NULL, 0) != 0 ||
        argmax <= (int)sizeof(int) || argmax > 1024 * 1024) {
        return false;
    }

    char *buffer = malloc((size_t)argmax);
    if (buffer == NULL) {
        return false;
    }
    size_t len = (size_t)argmax;
    int mib[] = { CTL_KERN, KERN_PROCARGS2, pid };
    if (sysctl(mib, 3, buffer, &len, NULL, 0) != 0 || len <= sizeof(int)) {
        free(buffer);
        return false;
    }

    int argc = 0;
    memcpy(&argc, buffer, sizeof(argc));
    char *cursor = buffer + sizeof(argc);
    char *end = buffer + len;
    if (argc <= 0) {
        free(buffer);
        return false;
    }

    size_t executable_len = strnlen(cursor, (size_t)(end - cursor));
    if (executable_len == (size_t)(end - cursor)) {
        free(buffer);
        return false;
    }
    cursor += executable_len + 1;
    while (cursor < end && *cursor == '\0') cursor++;

    for (int index = 0; index < argc; index++) {
        if (cursor >= end) {
            free(buffer);
            return false;
        }
        size_t remaining = (size_t)(end - cursor);
        size_t value_len = strnlen(cursor, remaining);
        if (value_len == 0 || value_len == remaining) {
            free(buffer);
            return false;
        }
        cursor += value_len + 1;
    }
    while (cursor < end && *cursor == '\0') cursor++;

    size_t key_len = strlen(key);
    const char *match = NULL;
    size_t match_len = 0;
    while (cursor < end && *cursor != '\0') {
        size_t entry_len = strnlen(cursor, (size_t)(end - cursor));
        if (entry_len == (size_t)(end - cursor)) {
            free(buffer);
            return false;
        }
        if (entry_len > key_len && cursor[key_len] == '=' &&
            memcmp(cursor, key, key_len) == 0) {
            if (match != NULL) {
                free(buffer);
                return false;
            }
            match = cursor + key_len + 1;
            match_len = entry_len - key_len - 1;
        }
        cursor += entry_len + 1;
    }

    if (match == NULL || match_len + 1 > out_len) {
        free(buffer);
        return false;
    }
    memcpy(out, match, match_len);
    out[match_len] = '\0';
    free(buffer);
    return true;
}

bool av_process_cwd(pid_t pid, char *out, size_t out_len) {
    if (out_len == 0) {
        return false;
    }
    struct proc_vnodepathinfo info;
    memset(&info, 0, sizeof(info));
    int size = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info));
    if (size != sizeof(info) || info.pvi_cdir.vip_path[0] == '\0') {
        return false;
    }
    size_t len = strnlen(info.pvi_cdir.vip_path, sizeof(info.pvi_cdir.vip_path));
    if (len >= out_len) {
        return false;
    }
    memcpy(out, info.pvi_cdir.vip_path, len + 1);
    return true;
}
