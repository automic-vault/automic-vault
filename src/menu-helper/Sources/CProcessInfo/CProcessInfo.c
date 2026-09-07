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
    for (int i = 0; i < argc && cursor < end && written + 1 < out_len; i++) {
        size_t arg_len = strnlen(cursor, (size_t)(end - cursor));
        if (arg_len == 0) {
            break;
        }
        if (i > 0 && written + 1 < out_len) {
            out[written++] = '\n';
        }
        size_t copy_len = arg_len;
        if (copy_len > out_len - written - 1) {
            copy_len = out_len - written - 1;
        }
        memcpy(out + written, cursor, copy_len);
        written += copy_len;
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

// XNU's stable 56-byte PROC_PIDUNIQIDENTIFIERINFO ABI (flavor 17).
// The original-parent version was reserved on older kernels; zero fails closed.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
struct av_unique_info {
    uint8_t uuid[16];
    uint64_t unique_id, parent_unique_id;
    int32_t version, original_parent_version;
    uint64_t reserved[2];
};
_Static_assert(sizeof(struct av_unique_info) == 56, "process execution ABI");

static bool unique_info(pid_t pid, struct av_unique_info *info) {
    return proc_pidinfo(pid, 17, 0, info, sizeof(*info)) == sizeof(*info);
}

bool av_original_parent_tracking_available(void) {
    struct av_unique_info info = {0};
    return unique_info(getpid(), &info) && info.original_parent_version > 0;
}

bool av_original_parent_identity(const AVProcessIdentity *child, AVProcessIdentity *parent_out) {
    struct av_unique_info original = {0}, parent = {0};
    return child->ppid > 1 && unique_info(child->pid, &original) &&
        original.version == child->pidversion && original.original_parent_version > 0 &&
        av_process_identity(child->ppid, parent_out) && unique_info(child->ppid, &parent) &&
        original.parent_unique_id == parent.unique_id &&
        original.original_parent_version == parent.version && parent.version == parent_out->pidversion &&
        child->euid == parent_out->euid && child->audit_session_id == parent_out->audit_session_id;
}

// LOCAL_PEERTOKEN resolves the most recent socket accessor's *current* task.
// Also require its recorded executable UUID and ownership of the exact peer endpoint.
bool av_socket_peer_identity(int fd, AVProcessIdentity *identity_out) {
    audit_token_t token = {0};
    uint8_t uuid[16] = {0}, zero_uuid[16] = {0};
    socklen_t token_size = sizeof(token), uuid_size = sizeof(uuid);
    struct av_unique_info before = {0}, after = {0};
    struct socket_fdinfo local = {0};
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &token_size) != 0 ||
        token_size != sizeof(token) || audit_token_to_euid(token) != geteuid() ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERUUID, uuid, &uuid_size) != 0 || uuid_size != sizeof(uuid) ||
        memcmp(uuid, zero_uuid, sizeof(uuid)) == 0 ||
        !av_process_identity(audit_token_to_pid(token), identity_out) ||
        !unique_info(identity_out->pid, &before) || memcmp(uuid, before.uuid, sizeof(uuid)) != 0 ||
        before.version != audit_token_to_pidversion(token) ||
        identity_out->pidversion != before.version || identity_out->euid != audit_token_to_euid(token) ||
        identity_out->audit_session_id != (uint32_t)audit_token_to_asid(token) ||
        proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &local, sizeof(local)) != sizeof(local) ||
        local.psi.soi_kind != SOCKINFO_UN || local.psi.soi_type != SOCK_STREAM ||
        local.psi.soi_proto.pri_un.unsi_conn_so == 0) return false;
    // Bound inspection rather than allocating from an untrusted descriptor count.
    struct proc_fdinfo descriptors[4096];
    int bytes = proc_pidinfo(identity_out->pid, PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (bytes <= 0 || bytes >= (int)sizeof(descriptors) || bytes % sizeof(descriptors[0]) != 0) return false;
    bool owns_peer = false;
    for (size_t i = 0; i < (size_t)bytes / sizeof(descriptors[0]); i++) {
        if (descriptors[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo peer = {0};
        if (proc_pidfdinfo(identity_out->pid, descriptors[i].proc_fd, PROC_PIDFDSOCKETINFO,
                          &peer, sizeof(peer)) != sizeof(peer)) continue;
        if (peer.psi.soi_kind == SOCKINFO_UN && peer.psi.soi_type == SOCK_STREAM &&
            peer.psi.soi_so == local.psi.soi_proto.pri_un.unsi_conn_so &&
            peer.psi.soi_proto.pri_un.unsi_conn_so == local.psi.soi_so) {
            owns_peer = true;
            break;
        }
    }
    return owns_peer && unique_info(identity_out->pid, &after) &&
        before.unique_id == after.unique_id && before.version == after.version &&
        memcmp(before.uuid, after.uuid, sizeof(uuid)) == 0;
}

bool av_process_cwd(pid_t pid, char *out, size_t out_len) {
    struct proc_vnodepathinfo info = {0};
    if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        info.pvi_cdir.vip_path[0] != '/' || strlen(info.pvi_cdir.vip_path) >= out_len) return false;
    strlcpy(out, info.pvi_cdir.vip_path, out_len);
    return true;
}

// Preserve every argument boundary, including empty strings and embedded newlines.
ssize_t av_process_arguments_data(pid_t pid, char *out, size_t out_len) {
    if (out_len <= sizeof(int)) return -1;
    size_t len = out_len;
    int mib[] = { CTL_KERN, KERN_PROCARGS2, pid };
    if (sysctl(mib, 3, out, &len, NULL, 0) != 0 || len <= sizeof(int)) return -1;
    int argc = 0;
    memcpy(&argc, out, sizeof(argc));
    if (argc <= 0) return -1;
    char *cursor = out + sizeof(argc), *end = out + len;
    size_t path_len = strnlen(cursor, (size_t)(end - cursor));
    if (path_len == (size_t)(end - cursor)) return -1;
    cursor += path_len + 1;
    while (cursor < end && *cursor == 0) cursor++;
    char *start = cursor;
    for (int i = 0; i < argc; i++) {
        if (cursor >= end) return -1;
        size_t size = strnlen(cursor, (size_t)(end - cursor));
        if (size == (size_t)(end - cursor)) return -1;
        cursor += size + 1;
    }
    size_t bytes = (size_t)(cursor - start);
    memmove(out, start, bytes);
    return (ssize_t)bytes;
}
