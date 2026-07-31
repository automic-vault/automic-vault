#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE 4096
#endif

typedef struct {
    pid_t pid;
    pid_t ppid;
    pid_t sid;
    uint64_t start_usec;
    int pidversion;
    uid_t euid;
    uint32_t audit_session_id;
    char path[PROC_PIDPATHINFO_MAXSIZE];
} AVProcessIdentity;

bool av_peer_pid(int fd, pid_t *pid_out);
bool av_process_identity(pid_t pid, AVProcessIdentity *identity_out);
bool av_process_arguments(pid_t pid, char *out, size_t out_len);
bool av_process_environment_value(pid_t pid, const char *key, char *out, size_t out_len);
bool av_process_cwd(pid_t pid, char *out, size_t out_len);
