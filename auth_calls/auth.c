#define __TARGET_ARCH_x86
#include "../vmlinux/vmlinux.h"
#include "auth.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

static __always_inline int str_eq(const char* a , const char* b, int size){

    #pragma unroll
    for (int i = 0; i < size ; i++){
        char c1 = a[i];
        char c2 = b[i];
        if (c1 != c2){
            return 0;
        }
        if (c1 == '\0')
            break;
    }
    return 1;
}


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[64]);
    __type(value, __u8);
} comm_filtering SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 512 * 32); // 8mb
} file_events SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    // pid
    __type(value, TrackFileChanges);
} pam_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32);
    __type(value, TrackFileChanges);
} scratchpad_map_pam_authenticate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32);
    __type(value, TrackFileChanges);
} scratchpad_map_pam_chauthtok SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32);
    __type(value, TrackFileChanges);
} scratchpad_map_pam_setcredentials SEC(".maps");



SEC("uprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_authenticate")
int BPF_UPROBE(pam_authenticate_enter, pam_handle_t *pamh, int flags){

    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid; 
    if (my_pid)
    {
        if (*my_pid == pid)
        {
            return 0;
        }
    }
    
    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == pid_tgid) {
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        __u32 scratch_key = 0;
        TrackFileChanges *blank_e = bpf_map_lookup_elem(&scratchpad_map_pam_authenticate, &scratch_key);
        if (!blank_e) {
            bpf_printk("Failed to get scratchpad\n");
            return 0; // Should not happen for an array map with max_entries=1
        }
        int update = bpf_map_update_elem(&pam_calls, &pid, blank_e, BPF_ANY);
        if (update < 0) {
            bpf_printk("uprobe_pam_autenticate: Failed to insert pid %d. Ret: %d\n", pid, update);
            return 0;
        }

        // Relookup to get the valid per-CPU pointer 'e' (required by verifier)
        event = bpf_map_lookup_elem(&pam_calls, &pid);
        if (!event) {
            bpf_printk("uprobe_pam_autenticate: Failed to get pointer after update for pid %d\n", pid);
            return 0;
        }
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    
    // address of the command (ssh , ftp , etc)
    __u64 service_name_addr = 0;
    bpf_probe_read_user(&service_name_addr, sizeof(service_name_addr), &pamh->service_name);
    // address of the user who tries to do the connection/ password input
    __u64 username_addr = 0;
    bpf_probe_read_user(&username_addr, sizeof(username_addr), &pamh->user);
    // remote host/ip , may be NULL for login prompt which is not from external
    __u64 rhost_address = 0;
    bpf_probe_read_user(&rhost_address, sizeof(rhost_address), &pamh->rhost);
    // remote name who logs in , may be NULL for login prompt which is not from external
    __u64 rname_address = 0;
    bpf_probe_read_user(&rname_address, sizeof(rname_address), &pamh->ruser);
    // tty 
    __u64 tty_addr = 0;
    bpf_probe_read_user(&tty_addr, sizeof(tty_addr), &pamh->tty);

    event->__generics.pid = pid;
    event->__generics.ppid = realPPID;
    event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    event->__generics.evt_type = EVENT_AUTH;
    bpf_probe_read_user_str(event->__generics.comm,sizeof(event->__generics.comm),(const void*)service_name_addr);
    // the username from where i m tryin to do the login
    bpf_probe_read_user_str(event->__auth.name,sizeof(event->__auth.name),(const void*)username_addr);
    // login type ( ssh , ftp, etc) name of the service , later correlating with comm , but helps with ml 
    bpf_probe_read_user_str(event->__auth.login_type,sizeof(event->__auth.login_type),(const void*)service_name_addr);
    bpf_probe_read_user_str(event->__auth.rhost,sizeof(event->__auth.rhost),(const void*)rhost_address);
    bpf_probe_read_user_str(event->__auth.rname,sizeof(event->__auth.rname),(const void*)rname_address);
    
    event->new_mode = -1;
    event->mode = -1;
    event->old_mtime = -1;
    event->new_mtime = -1;
    event->old_ctime = -1;
    event->new_ctime = -1;
    event->old_atime = -1;
    event->new_atime = -1;

    event->comm_timestamp = bpf_ktime_get_tai_ns();
    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++) {
        __builtin_memset(event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    __builtin_memcpy(event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    // maybe file_type , idk
    __builtin_memcpy(event->file_type, "void", sizeof("void"));
    __builtin_memcpy(event->file_type_new, "void", sizeof("void"));
    
    event->is_sensitive_file = -1;
    event->was_suid_changed = -1;
    event->suid_set = -1;
    event->suid_cleared = -1;
    event->was_sgid_changed = -1;
    event->sgid_set = -1;
    event->sgid_cleared = -1;
    
    event->was_sticky_changed = -1;
    event->sticky_set = -1;
    event->sticky_cleared = -1;

    event->was_permission_changed = -1;
    event->was_owner_changed = -1;
    event->was_group_changed = -1;
   
    event->was_file_modified = -1;
    event->was_creation_time_changed = -1;
    event->was_access_time_changed = -1;
    event->was_modified_time_changed = -1;

    // socket
    event->__sock.protocol_family = -1;
    event->__sock.socket_type= -1;
    event->__sock.protocol = -1;
    event->__sock.is_important_port = -1;
    event->__sock.port = -1;
    event->__sock.ipv4 = -1;
    event->__sock.local_ipv4_socket_addr = -1;
    event->__sock.local_socket_port = -1;
    event->__sock.peer_pid = -1;
    event->__sock.peer_uid = -1;
    event->__sock.peer_gid = -1;
    event->__sock.backlog_value = -1;
    event->__sock.ifindex = -1;
    event->__sock.kernel_sock = -1;
    event->__sock.is_success = -1;
    // ---
    event->was_file_created = -1;
    event->dev_major = 1;
    event->dev_major_new = 1;
    event->dev_minor = 1;
    event->dev_minor_new = 1;
    event->rdev_minor = -1;
    event->rdev_major = -1;
    // ---
    event->is_target_dir_world_writable = -1;
    event->is_linked_file_SGID_or_SUID = -1;
    event->is_linked_to_sensitive_file = -1;
    event->is_cross_user_link = -1;
  
    __builtin_memcpy(event->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(event->new_filename, "void", sizeof("void"));
    
    event->is_symlink = -1;
    event->was_dir_removed = -1;
    // ----
    event->is_current_dir_world_writable = -1;
    event->rdev_major_new = -1;
    event->rdev_minor_new = -1;
   
    return 0;

}

SEC("uretprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_authenticate")
int BPF_URETPROBE(pam_authenticate_exit, int ret){
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        bpf_printk("No auth event found in the map. Check the pam_authenticate uprobe");
        return 0;
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    event->__generics.duration_ns = bpf_ktime_get_ns() - start_time;

    event->__auth.is_switching_root = 0;
    event->__auth.is_switching_user = 0;
    event->__auth.is_changing_password = 0;
    event->__auth.is_root_command = 0;
    event->__generics.exit_code = ret;


    if (ret == 0){
        bpf_printk("Succesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 1;
    }else{
        bpf_printk("Unsuccesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 0;
    }


    TrackFileChanges *out = bpf_ringbuf_reserve(&file_events, sizeof(*out), 0);
    if (!out) {
        bpf_printk("Ringbuf reserve failed for pid=%d\n", pid);
        return 0;
    }

    int read = bpf_probe_read_kernel(out, sizeof(*out), event);
    if (read != 0){
        bpf_printk("(uretprobe in pam_authenticate)\n");
        bpf_printk("Failed to copy from stored event(pam_authenticate) to out buffer\n");
        bpf_ringbuf_discard(out,0);
        return 0;
    }

    bpf_printk("Emiting pam_auth_exit event\n");
    bpf_ringbuf_submit(out,0);

    int delete = bpf_map_delete_elem(&pam_calls, &pid);
    bpf_printk("Delete return -> %d\n",delete);
    if (delete != 0){
        bpf_printk("(uretprobe in pam_authenticate)\n");
        bpf_printk("(fail)Failed to delete entry from pam_calls map\n");
    }else{
        bpf_printk("(uretprobe in pam_authenticate)\n");
        bpf_printk("(notfail)Succefully deleted pid from pam_calls map\n");

    }
    
    return 0;

}


SEC("uprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_chauthtok")
int BPF_UPROBE(pam_chauthtok_entry, pam_handle_t* pamh, int flags){
__u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid; 
    if (my_pid)
    {
        if (*my_pid == pid)
        {
            bpf_printk("PID STORED IN MAP -> %d \n", *my_pid);
            bpf_printk("CURRENT PID -> %d \n", pid);
            bpf_printk("PID OF CURRENT EXECUTABLE (sys_enter_openat)\n");
            return 0;
        }
    }

    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == pid_tgid) {
            return 0;
        }
    }


    char comm[TYPE];
    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }


    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        __u32 scratch_key = 0;
        TrackFileChanges *blank_e = bpf_map_lookup_elem(&scratchpad_map_pam_chauthtok, &scratch_key);
        if (!blank_e) {
            bpf_printk("Failed to get scratchpad\n");
            return 0; // Should not happen for an array map with max_entries=1
        }
        int update = bpf_map_update_elem(&pam_calls, &pid, blank_e, BPF_ANY);
        if (update < 0) {
            bpf_printk("uprobe_pam_chauthtok: Failed to insert pid %d. Ret: %d\n", pid, update);
            return 0;
        }

        // Relookup to get the valid per-CPU pointer 'e' (required by verifier)
        event = bpf_map_lookup_elem(&pam_calls, &pid);
        if (!event) {
            bpf_printk("uprobe_pam_chauthtok: Failed to get pointer after update for pid %d\n", pid);
            return 0;
        }
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    // address of the command (ssh , ftp , etc)
    __u64 service_name_addr = 0;
    bpf_probe_read_user(&service_name_addr, sizeof(service_name_addr), &pamh->service_name);
    // address of the user who tries to do the connection/ password input
    __u64 username_addr = 0;
    bpf_probe_read_user(&username_addr, sizeof(username_addr), &pamh->user);
    // remote host/ip , may be NULL for login prompt which is not from external
    __u64 rhost_address = 0;
    bpf_probe_read_user(&rhost_address, sizeof(rhost_address), &pamh->rhost);
    // remote name who logs in , may be NULL for login prompt which is not from external
    __u64 rname_address = 0;
    bpf_probe_read_user(&rname_address, sizeof(rname_address), &pamh->ruser);
    // tty 
    __u64 tty_addr = 0;
    bpf_probe_read_user(&tty_addr, sizeof(tty_addr), &pamh->tty);

    event->__generics.pid = pid;
    event->__generics.ppid = realPPID;
    event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    event->__generics.evt_type = EVENT_PASSWD_CHANGE;
    bpf_probe_read_user_str(event->__generics.comm,sizeof(event->__generics.comm),(const void*)service_name_addr);
    // the username from where i m tryin to do the login
    bpf_probe_read_user_str(event->__auth.name,sizeof(event->__auth.name),(const void*)username_addr);
    // login type ( ssh , ftp, etc) name of the service , later correlating with comm , but helps with ml 
    bpf_probe_read_user_str(event->__auth.login_type,sizeof(event->__auth.login_type),(const void*)service_name_addr);
    bpf_probe_read_user_str(event->__auth.rhost,sizeof(event->__auth.rhost),(const void*)rhost_address);
    bpf_probe_read_user_str(event->__auth.rname,sizeof(event->__auth.rname),(const void*)rname_address);
    
    event->new_mode = -1;
    event->mode = -1;
    // to complete uid,gid
    event->old_mtime = -1;
    event->new_mtime = -1;
    event->old_ctime = -1;
    event->new_ctime = -1;
    event->old_atime = -1;
    event->new_atime = -1;

    event->comm_timestamp = bpf_ktime_get_tai_ns();
    // maybe file_type , idk
    bpf_probe_read_user_str(event->file_type,sizeof(event->file_type),(const void*)"void");
    bpf_probe_read_user_str(event->file_type_new,sizeof(event->file_type_new),(const void*)"void");
    bpf_probe_read_user_str(event->__generics.filename,sizeof(event->__generics.filename),(const void*)"void");
    bpf_probe_read_user_str(event->new_filename,sizeof(event->new_filename),(const void*)"void");
    bpf_probe_read_user_str(event->__sock.path,sizeof(event->__sock.path),(const void*)"void");
    bpf_probe_read_user_str(event->__sock.local_ipv6_socket_addr,sizeof(event->__sock.local_ipv6_socket_addr),(const void*)"void");
    // ---
    event->is_sensitive_file = -1;
    event->was_suid_changed = -1;
    event->suid_set = -1;
    event->suid_cleared = -1;
    // ---
    event->was_sgid_changed = -1;
    event->sgid_set = -1;
    event->sgid_cleared = -1;
    // ---
    event->was_sticky_changed = -1;
    event->sticky_set = -1;
    event->sticky_cleared = -1;
    // ---
    event->was_permission_changed = -1;
    event->was_owner_changed = -1;
    event->was_group_changed = -1;
    event->was_file_modified = -1;
    event->was_creation_time_changed = -1;
    event->was_access_time_changed = -1;
    event->was_modified_time_changed = -1;

    // socket
    event->__sock.protocol_family = -1;
    event->__sock.socket_type= -1;
    event->__sock.protocol = -1;
    event->__sock.is_important_port = -1;
    event->__sock.port = -1;
    event->__sock.ipv4 = -1;
    event->__sock.local_ipv4_socket_addr = -1;
    event->__sock.local_socket_port = -1;
    event->__sock.peer_pid = -1;
    event->__sock.peer_uid = -1;
    event->__sock.peer_gid = -1;
    event->__sock.backlog_value = -1;
    event->__sock.ifindex = -1;
    event->__sock.kernel_sock = -1;
    event->__sock.is_success = -1;

    // ---
    event->was_file_created = -1;
    event->dev_major = 1;
    event->dev_major_new = 1;
    event->dev_minor = 1;
    event->dev_minor_new = 1;
    event->rdev_minor = -1;
    event->rdev_major = -1;

    // ---
    event->is_target_dir_world_writable = -1;
    event->is_linked_file_SGID_or_SUID = -1;
    event->is_linked_to_sensitive_file = -1;
    event->is_cross_user_link = -1;
    // ---
    event->is_symlink = -1;
    event->was_dir_removed = -1;
    // ----
    event->is_current_dir_world_writable = -1;
    event->rdev_major_new = -1;
    event->rdev_minor_new = -1;
  

    return 0;
}

SEC("uretprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_chauthtok")
int BPF_URETPROBE(pam_chauthtok_exit , int ret){
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        bpf_printk("No auth event found in the map. Check the pam_chauthtok uprobe");
        return 0;
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    event->__generics.duration_ns = bpf_ktime_get_ns() - start_time;


    event->__auth.is_switching_root = 0;
    event->__auth.is_switching_user = 0;
    event->__auth.is_changing_password = 1;
    event->__auth.is_root_command = 0;
    event->__generics.exit_code = ret;


    // if success
    if (ret == 0){
        bpf_printk("Succesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 1;
    }else{
        bpf_printk("Unsuccesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 0;
    }

    TrackFileChanges *out = bpf_ringbuf_reserve(&file_events, sizeof(*out), 0);
    if (!out) {
        bpf_printk("Ringbuf reserve failed for pid=%d\n", pid);
        return 0;
    }

    int read = bpf_probe_read_kernel(out, sizeof(*out), event);
    if (read != 0){
        bpf_printk("(uretprobe in pam_chauthtok)\nFailed to copy from stored event(pam_chauthtok) to out buffer\n");
        bpf_ringbuf_discard(out,0);
        return 0;
    }

    bpf_printk("Emiting pam_chauthtok_exit event\n");
    bpf_ringbuf_submit(out,0);

    int delete = bpf_map_delete_elem(&pam_calls, &pid);
    if (delete != 0){
        bpf_printk("(uretprobe in pam_chauthtok)\nFailed to delete entry from pam_calls map\n");
    }
    
    return 0;
}


SEC("uprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_setcred")
int BPF_UPROBE(pam_setcred_entry, pam_handle_t* pamh, int flags){
__u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = (__u32)pid_tgid; 
    if (my_pid)
    {
        if (*my_pid == pid)
        {
            return 0;
        }
    }
    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == pid_tgid) {
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }


    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        __u32 scratch_key = 0;
        TrackFileChanges *blank_e = bpf_map_lookup_elem(&scratchpad_map_pam_setcredentials, &scratch_key);
        if (!blank_e) {
            bpf_printk("Failed to get scratchpad_map_pam_setcredentials\n");
            return 0; // Should not happen for an array map with max_entries=1
        }
        int update = bpf_map_update_elem(&pam_calls, &pid, blank_e, BPF_ANY);
        if (update < 0) {
            bpf_printk("uprobe_pam_set_cred_entry: Failed to insert pid %d. Ret: %d\n", pid, update);
            return 0;
        }

        // Relookup to get the valid per-CPU pointer 'e' (required by verifier)
        event = bpf_map_lookup_elem(&pam_calls, &pid);
        if (!event) {
            bpf_printk("uprobe_pam_set_cred_entry: Failed to get pointer after update for pid %d\n", pid);
            return 0;
        }
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    // address of the command (ssh , ftp , etc)
    __u64 service_name_addr = 0;
    bpf_probe_read_user(&service_name_addr, sizeof(service_name_addr), &pamh->service_name);
    // address of the user who tries to do the connection/ password input
    __u64 username_addr = 0;
    bpf_probe_read_user(&username_addr, sizeof(username_addr), &pamh->user);
    // remote host/ip , may be NULL for login prompt which is not from external
    __u64 rhost_address = 0;
    bpf_probe_read_user(&rhost_address, sizeof(rhost_address), &pamh->rhost);
    // remote name who logs in , may be NULL for login prompt which is not from external
    __u64 rname_address = 0;
    bpf_probe_read_user(&rname_address, sizeof(rname_address), &pamh->ruser);
    // tty 
    __u64 tty_addr = 0;
    bpf_probe_read_user(&tty_addr, sizeof(tty_addr), &pamh->tty);

    event->__generics.pid = pid;
    event->__generics.ppid = realPPID;
    event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    event->__generics.evt_type = EVENT_CHANGE_USER;
    bpf_probe_read_user_str(event->__generics.comm,sizeof(event->__generics.comm),(const void*)service_name_addr);
    // the username from where i m tryin to do the login
    bpf_probe_read_user_str(event->__auth.name,sizeof(event->__auth.name),(const void*)username_addr);
    // login type ( ssh , ftp, etc) name of the service , later correlating with comm , but helps with ml 
    bpf_probe_read_user_str(event->__auth.login_type,sizeof(event->__auth.login_type),(const void*)service_name_addr);
    bpf_probe_read_user_str(event->__auth.rhost,sizeof(event->__auth.rhost),(const void*)rhost_address);
    bpf_probe_read_user_str(event->__auth.rname,sizeof(event->__auth.rname),(const void*)rname_address);
   
    
    event->new_mode = -1;
    event->mode = -1;

    event->old_mtime = -1;
    event->new_mtime = -1;
    event->old_ctime = -1;
    event->new_ctime = -1;
    event->old_atime = -1;
    event->new_atime = -1;

    event->comm_timestamp = bpf_ktime_get_tai_ns();
    bpf_probe_read_user_str(event->file_type,sizeof(event->file_type),(const void*)"void");
    bpf_probe_read_user_str(event->file_type_new,sizeof(event->file_type_new),(const void*)"void");
    bpf_probe_read_user_str(event->__generics.filename,sizeof(event->__generics.filename),(const void*)"void");
    bpf_probe_read_user_str(event->new_filename,sizeof(event->new_filename),(const void*)"void");
    bpf_probe_read_user_str(event->__sock.path,sizeof(event->__sock.path),(const void*)"void");
    bpf_probe_read_user_str(event->__sock.local_ipv6_socket_addr,sizeof(event->__sock.local_ipv6_socket_addr),(const void*)"void");

    // ---
    event->is_sensitive_file = -1;
    event->was_suid_changed = -1;
    event->suid_set = -1;
    event->suid_cleared = -1;
    // ---
    event->was_sgid_changed = -1;
    event->sgid_set = -1;
    event->sgid_cleared = -1;
    // ---
    event->was_sticky_changed = -1;
    event->sticky_set = -1;
    event->sticky_cleared = -1;
    // ---
    event->was_permission_changed = -1;
    event->was_owner_changed = -1;
    event->was_group_changed = -1;
   
    event->was_file_modified = -1;
    event->was_creation_time_changed = -1;
    event->was_access_time_changed = -1;
    event->was_modified_time_changed = -1;
    // socket
    event->__sock.protocol_family = -1;
    event->__sock.socket_type= -1;
    event->__sock.protocol = -1;
    event->__sock.is_important_port = -1;
    event->__sock.port = -1;
    event->__sock.ipv4 = -1;
    event->__sock.local_ipv4_socket_addr = -1;
    event->__sock.local_socket_port = -1;
    event->__sock.peer_pid = -1;
    event->__sock.peer_uid = -1;
    event->__sock.peer_gid = -1;
    event->__sock.backlog_value = -1;
    event->__sock.ifindex = -1;
    event->__sock.kernel_sock = -1;
    event->__sock.is_success = -1;

    // ---
    event->was_file_created = -1;
    event->dev_major = 1;
    event->dev_major_new = 1;
    event->dev_minor = 1;
    event->dev_minor_new = 1;
    event->rdev_minor = -1;
    event->rdev_major = -1;
   
    // ---
    event->is_target_dir_world_writable = -1;
    event->is_linked_file_SGID_or_SUID = -1;
    event->is_linked_to_sensitive_file = -1;
    event->is_cross_user_link = -1;
    // ---
    event->is_symlink = -1;
    event->was_dir_removed = -1;
    // ----
    event->is_current_dir_world_writable = -1;
    event->rdev_major_new = -1;
    event->rdev_minor_new = -1;
    
    return 0;
}

SEC("uretprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_setcred")
int BPF_URETPROBE(pam_set_exit , int ret){
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int cpuid = bpf_get_smp_processor_id();
    TrackFileChanges *event = bpf_map_lookup_elem(&pam_calls, &pid);
    if (!event){
        bpf_printk("No auth event found in the map. Check the pam_setcred uprobe");
        return 0;
    }

    struct task_struct* task = (struct task_struct*) bpf_get_current_task();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    event->__generics.duration_ns = bpf_ktime_get_ns() - start_time;


    event->__auth.is_switching_root = 0; //
    event->__auth.is_switching_user = 0; // 
    event->__auth.is_changing_password = 0;
    event->__auth.is_root_command = 0;
    event->__generics.exit_code = ret;
    

    bpf_probe_read_user_str(event->new_filename,sizeof(event->new_filename),(const void*)"void");
    bpf_probe_read_user_str(event->__generics.filename,sizeof(event->__generics.filename),(const void*)"void");

    if (str_eq(event->__auth.name, "root", 5)) {
        event->__auth.is_switching_root = 1;
    } else {
        event->__auth.is_switching_user = 1;
    }

    // if success
    if (ret == 0){
        bpf_printk("Succesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 1;
    }else{
        bpf_printk("Unsuccesfully auth for pid [%d]\n" , pid);
        event->__auth.is_success = 0;
    }

    TrackFileChanges *out = bpf_ringbuf_reserve(&file_events, sizeof(*out), 0);
    if (!out) {
        bpf_printk("Ringbuf reserve failed for pid=%d\n", pid);
        return 0;
    }

    int read = bpf_probe_read_kernel(out, sizeof(*out), event);
    if (read != 0){
        bpf_printk("(uretprobe in pam_setcred)\nFailed to copy from stored event(pam_setcred) to out buffer\n");
        bpf_ringbuf_discard(out,0);
        return 0;
    }

    bpf_printk("Emiting pam_setcred_exit event\n");
    bpf_ringbuf_submit(out,0);


    int delete = bpf_map_delete_elem(&pam_calls, &pid);
    if (delete != 0){
        bpf_printk("(uretprobe in pam_setcred)\nFailed to delete entry from pam_calls map\n");
        return 0;
    }
    
    return 0;
}



char LICENSE[] SEC("license") = "GPL";


