#include "../vmlinux/vmlinux.h"
#include "process_exec.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    
    __type(value, u8);
} blocked_patterns_pids SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 512 * 32); // 8mb

} file_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TYPE]);
    __type(value, __u8);
} comm_filtering SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, bool);
} active_file_pids SEC(".maps");



SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx){
    pid_t pid, ppid, tgid;
    u64 id, ts, *start_ts, start_time = 0;
    __u64 uid_gid = bpf_get_current_uid_gid();

    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;
    pid  = id & 0xFFFFFFFF;


    __u32 key = 0;
    __u32 *my_pid = bpf_map_lookup_elem(&self_pid, &key);
    struct task_struct* task = (struct task_struct*) bpf_get_current_task();

    __u8 *isPatternPidBlocked = bpf_map_lookup_elem(&blocked_patterns_pids, &pid);
    if (isPatternPidBlocked){
        bpf_printk("brbrBlocked pattern pid <%d>\n", pid);
        int delete = bpf_map_delete_elem(&blocked_patterns_pids, &pid);
        if (delete < 0){
            bpf_printk("brbrFailed to delete from blocked_patterns_pid pid <%d>\n", pid);
        }else{
            bpf_printk("brbrSuccesfully deleted from  blocked_patterns_pids <pid %d >", pid);
            return 0;
        }
    }

    if (pid != tgid) {
        return 0;
    }


    if (my_pid){
        if (*my_pid == pid || *my_pid == tgid){
            return 0;
        }
    }

    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == ppid) {
            return 0;
        }
    }

    bpf_printk("PID [%d] - PPID [%d] - TGID [%d]\n", pid , ppid, tgid);


    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }


    TrackFileChanges *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e){
        bpf_printk("olxbpf_ringbuf_reserve failed for process exit event (sched_process_exit)\n");
        return 0;
    }

    start_time = BPF_CORE_READ(task, start_time);
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    e->__generics.evt_type = EVENT_PROCESS_EXIT;
    e->__generics.duration_ns = bpf_ktime_get_ns() - start_time;
    
    e->comm_timestamp = bpf_ktime_get_tai_ns();
    e->__generics.pid = pid;
    e->__generics.uid = uid_gid >> 32;
    e->__generics.gid = (u32) uid_gid;
    e->__generics.ppid = realPPID;
    e->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->__generics.comm, sizeof(e->__generics.comm));
    // auth default
    e->__auth.is_success = -1;
    e->__auth.is_switching_user = -1;
    e->__auth.is_switching_root = -1;
    e->__auth.is_changing_password = -1;
    e->__auth.is_root_command = -1;

    // socket default
    e->__sock.protocol_family = -1;
    e->__sock.socket_type= -1;
    e->__sock.protocol = -1;
    e->__sock.is_important_port = -1;
    e->__sock.port = -1;
    e->__sock.ipv4 = -1;
    e->__sock.local_ipv4_socket_addr = -1;
    e->__sock.local_socket_port = -1;
    e->__sock.peer_pid = -1;
    e->__sock.peer_uid = -1;
    e->__sock.peer_gid = -1;
    e->__sock.backlog_value = -1;
    e->__sock.ifindex = -1;
    e->__sock.kernel_sock = -1;
    e->__sock.is_success = -1;

    // file default
    e->new_mode = -1;
    e->mode = -1;
    e->old_uid = e->__generics.uid;
    e->new_uid = e->old_uid;
    e->old_gid = e->__generics.gid;
    e->new_gid = e->old_gid;
    e->old_mtime = -1;
    e->new_mtime = -1;
    e->old_ctime = -1;
    e->new_ctime = -1;
    e->old_atime = -1;
    e->new_atime = -1;

    __builtin_memcpy(e->file_type, "void", sizeof("void"));
    __builtin_memcpy(e->file_type_new, "void", sizeof("void"));
    __builtin_memcpy(e->new_filename, "void", sizeof("void"));
    __builtin_memcpy(e->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(e->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(e->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(e->__sock.ipv6, "void", sizeof("void"));


    /* Sensitive / suid / sgid / sticky / other flags */
    e->is_sensitive_file = -1;
    e->was_suid_changed = -1;
    e->suid_set = -1;
    e->suid_cleared = -1;
    e->was_sgid_changed = -1;
    e->sgid_set = -1;
    e->sgid_cleared = -1;
    e->was_sticky_changed = -1;
    e->sticky_set = -1;
    e->sticky_cleared = -1;

    e->was_permission_changed = -1;
    e->was_owner_changed = -1;
    e->was_group_changed = -1;
    e->was_creation_time_changed = -1;
    e->was_access_time_changed = -1;
    e->was_modified_time_changed = -1;


    /* Inode/file creation indicators */
    e->was_file_created = -1;

    /* Device numbers */
    e->rdev_minor = -1;
    e->rdev_major = -1;

    /* Link-related */
    e->is_target_dir_world_writable = -1;
    e->is_linked_file_SGID_or_SUID = -1;
    e->is_linked_to_sensitive_file = -1;
    e->is_cross_user_link = -1;

    /* Symlink / directory / rename indicators */
    e->is_symlink = -1;
    e->was_dir_removed = -1;
    e->is_current_dir_world_writable = -1;

    /* New inode device numbers (rename/move) */
    e->rdev_minor_new = -1;
    e->rdev_major_new = -1;

    bpf_map_delete_elem(&active_file_pids, &pid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
