// #include "exec.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include "../vmlinux.h"

#include "../vmlinux/vmlinux.h"
#include "exec.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * /usr/sbin/sshd -> sshd
*/
static __always_inline int findRunnable(char *dst, const char filename[MAX_CHAR_LEN])
{
    int last_slash = -1;

    #pragma unroll
    for (int i = 0; i < MAX_CHAR_LEN; i++) {
        if (filename[i] == 0)
            break;
        if (filename[i] == '/')
            last_slash = i;
    }

    int start = last_slash + 1;
    int j = 0;

    #pragma unroll
    for (int i = start; i < MAX_CHAR_LEN; i++) {
        if (filename[i] == 0)
            break;
        dst[j++] = filename[i];
        if (j >= MAX_CHAR_LEN - 1)
            break;
    }

    dst[j] = 0;
    return j;
}


struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");



struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_CHAR_LEN]);
    __type(value, __u8);
} blocked_filenames SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[TYPE_3]);
    __type(value, __u8);
} blocked_comms_from_filenames SEC(".maps");


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
    __type(key, u32);    // pid
    __type(value, TrackFileChanges);
} execve_calls SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32);
    __type(value, TrackFileChanges);
} scratchpad_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int trace_syscall_execve(struct trace_event_raw_sys_enter *ctx) {

    __u32 key = 0;
    __u32 *my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 ppid = (__u32)id;
    // bpf_printk("ccENTERED SYSCALL EXECVE ENTER\n");


    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            bpf_printk("(ZYZ)BLOCKED SYSCALL EXECVE ENTER FOR PID -> %d\n", pid);
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


    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    char name[MAX_CHAR_LEN] = {};
    char comm_from_filename[TYPE_3] = {};
    const char *filename = (const char *)ctx->args[0];
    bpf_core_read_user_str(name, sizeof(name), filename);
    findRunnable(comm_from_filename, name);
    // bpf_printk("Blocked filename at sys_call_execve << %s >> \n", comm_from_filename);
    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, name);
    if (isFilenameBlocked != NULL)
    {
        bpf_printk("bbrxBlocked filename at check_file_open << %s >> \n", name);
        return 0;
    }

    __u8 *isCommFromFilenameBlocked = bpf_map_lookup_elem(&blocked_comms_from_filenames, comm_from_filename);
    if (isCommFromFilenameBlocked != NULL)
    {
        
        bpf_printk("bbrxBlocked filename at check_file_open << %s >> \n", name);
        return 0;
    }

    bpf_printk("(ZYZ)ENTERED SYSCALL EXECVE ENTER FOR PID -> %d\n", pid);


    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *e = bpf_map_lookup_elem(&execve_calls, &pid);
    if (!e){
        // insert into the tmp map 
        __u32 scratch_key = 0;
        TrackFileChanges *blank_e = bpf_map_lookup_elem(&scratchpad_map, &scratch_key);
        if (!blank_e) {
            bpf_printk("ZXZXFailed to get scratchpad\n");
            return 0; 
        }
        
        int update = bpf_map_update_elem(&execve_calls, &pid, blank_e, BPF_ANY);
        if (update < 0) {
            bpf_printk("ZXZXexecve_enter: Failed to insert pid %d. Ret: %d\n", pid, update);
            return 0;
        }

        // Relookup to get the valid per-CPU pointer 'e' (required by verifier)
        e = bpf_map_lookup_elem(&execve_calls, &pid);
        if (!e) {
            bpf_printk("ZXZXexecve_enter: Failed to get pointer after update for pid %d\n", pid);
            return 0;
        }
    }
    
    const char *const *argv = (const char *const *)ctx->args[1];
    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->__generics.argv[i],
                                sizeof(e->__generics.argv[i]),
                                argp);
    }


    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    e->__generics.evt_type = EVENT_EXECVE;
    e->__generics.pid  = pid;
    e->__generics.ppid = realPPID;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->__generics.uid = uid_gid >> 32;
    e->__generics.gid = (u32) uid_gid;
    e->comm_timestamp = bpf_ktime_get_tai_ns();
    

    bpf_get_current_comm(e->__generics.comm, sizeof(e->__generics.comm));
    long retFilename = bpf_probe_read_user_str(e->__generics.filename,
                            sizeof(e->__generics.filename),
                            filename);
    long retNewFlename = bpf_probe_read_user_str(e->new_filename,
                            sizeof(e->new_filename),
                            filename);
    if(retFilename <= 1){
        __builtin_memcpy(e->__generics.filename, "void" , sizeof("void"));
    }
    if(retNewFlename <= 1){
        __builtin_memcpy(e->new_filename, "void" , sizeof("void"));
    }
    __builtin_memcpy(e->file_type, "void" , sizeof("void"));
    __builtin_memcpy(e->file_type_new, "void" , sizeof("void"));
    
    e->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_printk("ZXZXTYPE: %d\n", e->__generics.evt_type);
    bpf_printk("ZXZXSIZE: %d\n", (int)sizeof(TrackFileChanges));

    // auth default
    e->__auth.is_success = -1;
    e->__auth.is_switching_user = -1;
    e->__auth.is_switching_root = -1;
    e->__auth.is_changing_password = -1;
    e->__auth.is_root_command = -1;
    __builtin_memcpy(e->__auth.name, "void" , sizeof("void"));
    __builtin_memcpy(e->__auth.rhost, "void" , sizeof("void"));
    __builtin_memcpy(e->__auth.rname, "void" , sizeof("void"));
    __builtin_memcpy(e->__auth.login_type, "void" , sizeof("void"));

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
    __builtin_memcpy(e->__sock.path, "void" , sizeof("void"));
    __builtin_memcpy(e->__sock.ipv6, "void" , sizeof("void"));
    __builtin_memcpy(e->__sock.local_ipv6_socket_addr, "void" , sizeof("void"));

    // file default
    e->new_mode = -1;
    e->mode = -1;
    e->old_uid = e->__generics.uid;
    e->new_uid = e->old_uid;
    e->old_gid = e->__generics.gid;
    e->new_gid = e->old_gid;
    // e->old_size = -1;
    // e->new_size = -1;
    /* Default file-related fields to -1 */
    e->old_mtime = -1;
    e->new_mtime = -1;
    e->old_ctime = -1;
    e->new_ctime = -1;
    e->old_atime = -1;
    e->new_atime = -1;

    /* Strings */
    // __builtin_memset(e->file_type, 0, sizeof(e->file_type));
    // __builtin_memset(e->file_type_new, 0, sizeof(e->file_type_new));
    // __builtin_memset(e->new_filename, 0, sizeof(e->new_filename));

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
    // e->was_size_extended = -1;
    // e->was_size_truncated = -1;
    e->was_creation_time_changed = -1;
    e->was_access_time_changed = -1;
    e->was_modified_time_changed = -1;
    

    /* Inode/file creation indicators */
    e->was_file_created = -1;

    /* Device numbers */
    e->rdev_minor = -1;
    e->rdev_major = -1;
    // e->i_bdev_major = -1;
    // e->i_bdev_minor = -1;
    // e->is_rdev_bdev_mismatch = -1;
    // e->is_rdev_bdev_mismatch_new = -1;

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
    // e->i_bdev_major_new = -1;
    // e->i_bdev_minor_new = -1;


    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{

    int ret = ctx->ret;  // return value from execve()
    int cpuid = bpf_get_smp_processor_id();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    // bpf_printk("ccENTERED SYSCALL EXECVE EXIT FOR PID -> %d\n", pid);
    TrackFileChanges *e = bpf_map_lookup_elem(&execve_calls, &pid);
    if (!e){
        bpf_printk("No execve event found in the map. Check the execve_enter");
        return 0;
    }

    if (ret >= 0){
        bpf_printk("Succesfully execve for pid [%d]\n" , pid);
        e->was_success = 1;
    }else{
        bpf_printk("Unsuccesfully execve for pid [%d]\n" , pid);
        e->was_success = 0;
    }
    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    e->__generics.duration_ns = bpf_ktime_get_ns() - start_time;
    e->__generics.exit_code = ret;



    TrackFileChanges *out = bpf_ringbuf_reserve(&file_events, sizeof(*out), 0);
    if (!out) {
        bpf_printk("olxbpf_ringbuf reserve failed sys_exit_execve for pid=%d\n", pid);
        return 0;
    }

    int read = bpf_probe_read_kernel(out, sizeof(*out), e);
    if (read != 0){
        bpf_printk("(execve_exit)\nFailed to copy from stored event(execve_enter) to out buffer\n");
        bpf_ringbuf_discard(out,0);
        return 0;
    }

    bpf_printk("(execve_exit)Emiting execve event\n");
    bpf_ringbuf_submit(out,0);

    int delete = bpf_map_delete_elem(&execve_calls, &pid);
    if (delete != 0){
        bpf_printk("(execve_exit)\nFailed to delete entry from execve_calls map\n");
        // bpf_ringbuf_discard(out,0);
        // return 0;
    }

    return 0;
}



char LICENSE[] SEC("license") = "GPL";
