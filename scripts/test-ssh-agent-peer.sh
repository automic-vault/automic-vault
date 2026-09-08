#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d /tmp/av-ssh-peer-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
cat > "$scratch/check.c" <<'C'
#include "CProcessInfo.h"
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
 if(argc==3 && strcmp(argv[1],"--login-child")==0) {
   AVProcessIdentity child={0}, parent={0}, login={0};
   assert(av_process_identity(atoi(argv[2]),&child));
   assert(!av_original_parent_identity(&child,&parent));
   assert(av_original_login_parent_identity(&child,&parent));
   assert(av_process_identity(child.ppid,&login));
   assert(parent.pid==login.ppid && parent.euid==child.euid && parent.audit_session_id==child.audit_session_id);
   AVProcessIdentity changed=child; changed.pidversion++;
   assert(!av_original_login_parent_identity(&changed,&parent));
   changed=child; changed.audit_session_id++;
   assert(!av_original_login_parent_identity(&changed,&parent));
   changed=child; changed.euid++;
   assert(!av_original_login_parent_identity(&changed,&parent));
   puts("SSH original login relay checks passed"); return 0;
 }
 char args[65536]; ssize_t count=av_process_arguments_data(getpid(),args,sizeof(args));
 assert(count>0); char *cursor=args;
 for(int i=0;i<argc;i++) { assert(strcmp(cursor,argv[i])==0); cursor+=strlen(cursor)+1; }
 assert(cursor==args+count);
 assert(av_process_arguments_data(getpid(),args,4)==-1);
 char dir[]="/tmp/av-ssh-peer-XXXXXX"; assert(mkdtemp(dir));
 struct sockaddr_un addr={.sun_family=AF_UNIX};
 snprintf(addr.sun_path,sizeof(addr.sun_path),"%s/socket",dir);
 int server=socket(AF_UNIX,SOCK_STREAM,0); assert(server>=0);
 assert(bind(server,(void*)&addr,sizeof(addr))==0); assert(listen(server,1)==0);
 int channel[2], report[2]; assert(pipe(channel)==0); assert(pipe(report)==0);
 pid_t child=fork(); assert(child>=0);
 if(child==0) {
   close(channel[1]); close(report[0]);
   int client=socket(AF_UNIX,SOCK_STREAM,0); assert(connect(client,(void*)&addr,sizeof(addr))==0);
   pid_t nested=fork(); assert(nested>=0);
   if(nested==0) { close(client); pause(); _exit(0); }
   assert(write(report[1],&nested,sizeof(nested))==sizeof(nested));
   char b; read(channel[0],&b,1); execl("/bin/sleep","sleep","60",NULL); _exit(1);
 }
 close(channel[0]); int fd=accept(server,NULL,NULL); assert(fd>=0);
 AVProcessIdentity peer={0}; assert(av_socket_peer_identity(fd,&peer)); assert(peer.pid==child);
 AVProcessIdentity parent={0}; assert(av_original_parent_identity(&peer,&parent)); assert(parent.pid==getpid());
 assert(!av_original_login_parent_identity(&peer,&parent));
 AVProcessIdentity changed=peer; changed.pidversion++;
 assert(!av_original_parent_identity(&changed,&parent));
 assert(peer.pidversion>0); char cwd[4096]; assert(av_process_cwd(child,cwd,sizeof(cwd))); assert(cwd[0]=='/');
 close(report[1]); pid_t nested=0;
 assert(read(report[0],&nested,sizeof(nested))==sizeof(nested)); close(report[0]);
 AVProcessIdentity grandchild={0}; assert(av_process_identity(nested,&grandchild));
 assert(av_original_parent_identity(&grandchild,&parent)); assert(parent.pid==child);
 int version=peer.pidversion;
 write(channel[1],"x",1);
 AVProcessIdentity current={0};
 for(int i=0;i<200;i++) {
   assert(av_process_identity(child,&current));
   if(current.pidversion!=version) break;
   usleep(10000);
 }
 assert(current.pidversion!=version);
 assert(!av_socket_peer_identity(fd,&peer)); // Same PID after exec is a different execution.
 assert(!av_original_parent_identity(&grandchild,&parent)); // An exec cannot impersonate a child's original Launcher.
 kill(nested,SIGTERM); kill(child,SIGTERM);waitpid(child,NULL,0);
 assert(!av_socket_peer_identity(fd,&peer)); assert(!av_socket_peer_identity(channel[1],&peer));
 close(fd);close(channel[1]);
 // Inspect a signed Apple process as well as the synthetic fork fixture.
 int native_input[2]; assert(pipe(native_input)==0);
 pid_t native=fork(); assert(native>=0);
 if(native==0) {
   close(native_input[1]); assert(dup2(native_input[0],STDIN_FILENO)>=0);
   execl("/usr/bin/nc","nc","-U",addr.sun_path,NULL); _exit(1);
 }
 close(native_input[0]); int native_fd=accept(server,NULL,NULL); assert(native_fd>=0);
 assert(av_socket_peer_identity(native_fd,&peer)); assert(peer.pid==native);
 assert(av_original_parent_identity(&peer,&parent)); assert(parent.pid==getpid());
 kill(native,SIGTERM);waitpid(native,NULL,0);close(native_fd);close(native_input[1]);
 close(server);unlink(addr.sun_path);rmdir(dir);puts("SSH socket peer checks passed");
}
C
clang -Wall -Wextra -Werror \
  -I"$repo/src/menu-helper/Sources/CProcessInfo/include" \
  "$scratch/check.c" "$repo/src/menu-helper/Sources/CProcessInfo/CProcessInfo.c" \
  -lbsm -o "$scratch/check"
"$scratch/check" 'a b' $'a\nb' ''
if [[ -n "${AV_SSH_LOGIN_CHILD_PID:-}" ]]; then
  "$scratch/check" --login-child "$AV_SSH_LOGIN_CHILD_PID"
fi
