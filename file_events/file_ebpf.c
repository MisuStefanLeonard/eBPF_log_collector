/* file_ebpf.c */
#include "../vmlinux/vmlinux.h"
#include "file_exec.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    // pid
    __type(value, TrackFileChanges);
} active_file_pids SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    
    __type(value, u8);
} blocked_patterns_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32);
    __type(value, TrackFileChanges);
} temp_pid_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_CHAR_LEN]);
    __type(value, __u8);
} blocked_filenames SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LITTLE_MAP_SIZE);
    __type(key, __u32);
    __type(value, char[MAX_PATTERN_LEN]);
} blocked_patterns SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 512 * 32); 
} file_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TYPE]);
    __type(value, __u8);
} comm_filtering SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static __always_inline int iterate_cb(void *ctx, __u32 i)
{
    struct iterate_ctx *ictx = ctx;
    char *pattern = bpf_map_lookup_elem(&blocked_patterns, &i);
    if (!pattern)
        return 0; // continue loop

    if (bpf_strstr(ictx->filename, pattern) >= 0)
    {
        ictx->match_found = 1;
        return 1; // stop loop
    }

    return 0; // continue loop
}
#else
static char c_strstr(const char *str, const char *pattern)
{
    char c1, c2;
    int i, j;

    for (i = 0; i < MAX_ITERS_FOR_STRSTR; i++)
    {
        for (j = 0; i + j <= MAX_ITERS_FOR_STRSTR; j++)
        {
            bpf_probe_read_kernel(&c2, sizeof(c2), pattern + j);
            if (c2 == '\0')
            {
                return 1; // found match
            }
            if (i + j == MAX_ITERS_FOR_STRSTR)
            {
                break;
            }
            bpf_probe_read_kernel(&c1, sizeof(c1), str + j);
            if (c1 == '\0')
            {
                return 0; // not found
            }
            if (c1 != c2)
            {
                break;
            }
        }
        if (i + j == MAX_ITERS_FOR_STRSTR)
        {
            return 0;
        }
        str++;
    }

    return 0;
}

static int iterate_cb(u32 i, void *data)
{
    struct iterate_ctx *ctx = data;

    char *pattern_ptr = bpf_map_lookup_elem(&blocked_patterns, &i);
    if (!pattern_ptr)
    {
        return 0; // continue
    }

    int plen = 0;
    for (int k = 0; k < MAX_PATTERN_LEN; k++) {
        char c;
        bpf_probe_read_kernel(&c, sizeof(c), pattern_ptr + k);
        if (c == '\0')
            break;
        plen++;
    }

    if (plen == 0)
        return 0;

    char match = c_strstr(ctx->filename, pattern_ptr);

    if (match == 1)
    {
        ctx->match_found = 1;
        return 1; // stop loop
    }

    return 0; // continue
}
#endif

// Wrapper to call bpf_loop
static char iterate(const char *str)
{
    struct iterate_ctx ctx = {};
    ctx.match_found = 0;
    ctx.filename = str;
    bpf_loop(LITTLE_MAP_SIZE, iterate_cb, &ctx, 0);
    return ctx.match_found;
}

static __always_inline int block_pid_and_drop(__u32 pid) {
    __u8 temp = 1;
    int update = bpf_map_update_elem(&blocked_patterns_pids, &pid, &temp, BPF_ANY);
    if (update < 0) {
        bpf_printk("brbrFailed to update blocked_patterns_pids <pid %d >", pid);
    } else {
        bpf_printk("brbrSuccesfully blocked_patterns_pids <pid %d >", pid);
    }
    return 0; 
}

SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32) pid_tgid;

    
    TrackFileChanges *e = bpf_map_lookup_elem(&active_file_pids, &pid);
    if (!e){
        bpf_printk("No file_open event found in the map. Check the active_file_pids");
        return 0;
    }


    if (e->fptr != (__u64)file) {
        return 0;
    }

    if (e->has_emitted_read == 1) return 0;
    e->__generics.evt_type = EVENT_FILE_OPEN_AND_READ;

    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == tid) {
            bpf_printk("FFPid is %d - Tid is %d - pythonPid is %d", pid, tid , *pythonPid);
            return 0;
        }
    }

    TrackFileChanges *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
    {
        bpf_printk("(fexit:vfs_read) Ringbuf reserve failed for pid=%d\n", pid);
        return 0;
    }

   

    if (ret > 0) {
        e->was_file_modified = 0;
        e->was_success = 1;        
        e->has_emitted_read = 1;
        e->was_access_time_changed = 1;
    }

    e->comm_timestamp = bpf_ktime_get_tai_ns();
    int read = bpf_probe_read_kernel(event, sizeof(*event), e);
    if (read != 0){
        bpf_printk("(fexit:vfs_read)\nFailed to copy from stored event(active_file_pids) to out buffer\n");
        bpf_ringbuf_discard(event,0);
        return 0;
    }

     for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(e->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    bpf_printk("Emiting open_and_read_exit event\n");
    bpf_ringbuf_submit(event,0);

    return 0;

}

SEC("fexit/vfs_write")
int BPF_PROG(trace_vfs_write_exit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32) pid_tgid;

    
    TrackFileChanges *e = bpf_map_lookup_elem(&active_file_pids, &pid);
    if (!e){
        bpf_printk("No file_open event found in the map. Check the active_file_pids");
        return 0;
    }


    if (e->fptr != (__u64)file) {
        return 0;
    }

    if (e->has_emitted_write == 1) return 0;
    e->__generics.evt_type = EVENT_FILE_OPEN_AND_WRITE;

    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == tid) {
            bpf_printk("OOPid is %d - Tid is %d - pythonPid is %d", pid, tid , *pythonPid);
            return 0;
        }
    }

    TrackFileChanges *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
    {
        bpf_printk("(fexit:vfs_write) Ringbuf reserve failed for pid=%d\n", pid);
        return 0;
    }

    if (ret > 0) {
        e->was_file_modified = 1;
        e->was_success = 1;        
        e->has_emitted_write = 1;
    }

    e->comm_timestamp = bpf_ktime_get_tai_ns();
    int read = bpf_probe_read_kernel(event, sizeof(*event), e);
    if (read != 0){
        bpf_printk("(fexit:vfs_write)\nFailed to copy from stored event(active_file_pids) to out buffer\n");
        bpf_ringbuf_discard(event,0);
        return 0;
    }

    bpf_printk("Emiting open_and_exit event\n");
    bpf_ringbuf_submit(event,0);

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file)
{
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
            return 0;
        }
    }

    __u32 pythonKey = 1;
    __u32 *pythonPid = bpf_map_lookup_elem(&self_pid, &pythonKey);
    if (pythonPid) {
        if (*pythonPid == pid || *pythonPid == ppid) {
            bpf_printk("CCPid is %d - Tid is %d - pythonPid is %d", pid, ppid , *pythonPid);
            return 0;
        }
    }

    __u8 *is_pid_blocked = bpf_map_lookup_elem(&blocked_patterns_pids, &pid);
    if (is_pid_blocked) {
        return 0; 
    }

    char comm[TYPE];
    bpf_get_current_comm(comm, sizeof(comm));


    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    // char isMatch = iterate(comm);
    // if (isMatch == 1)
    // {
    //     u8 temp = 1;
    //     int update = bpf_map_update_elem(&blocked_patterns_pids, &pid, &temp, BPF_ANY);
    //     if (update < 0) {
    //         bpf_printk("brbrFailed to update blocked_patterns_pids <pid %d >", pid);
    //     }else{
    //         bpf_printk("brbrSuccesfully blocked_patterns_pids <pid %d >", pid);
    //     }
    //     return 0;
    // }
    if (iterate(comm) == 1) {
        return block_pid_and_drop(pid);
    }

    __u32 mode = BPF_CORE_READ(file, f_inode, i_mode);
    char name[MAX_CHAR_LEN] = {};
    bpf_core_read_str(name, sizeof(name), file->f_path.dentry->d_name.name);
    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, name);
    if (isFilenameBlocked != NULL)
    {
        bpf_printk("bbBlocked filename at check_file_open << %s >> \n", name);
        return 0;
    }
    
    // if (__builtin_strcmp(name, "trace_pipe") != 0 && __builtin_strcmp(name, "\0") != 0)
    // {
    //     char isMatch = iterate(name);
    //     if (isMatch == 1)
    //     {
    //         u8 temp = 1;
    //         int update = bpf_map_update_elem(&blocked_patterns_pids, &pid, &temp, BPF_ANY);
    //         if (update < 0) {
    //             bpf_printk("brbrFailed to update blocked_patterns_pids <pid %d >", pid);
    //         }else{
    //             bpf_printk("brbrSuccesfully blocked_patterns_pids <pid %d >", pid);
    //         }
    //         return 0;
    //     }

    // }
    if (name[0] != '\0' && __builtin_strcmp(name, "trace_pipe") != 0)
    {
        if (iterate(name) == 1) {
            return block_pid_and_drop(pid);
        }
    }



    TrackFileChanges *file_event = bpf_map_lookup_elem(&active_file_pids, &pid);
    if (!file_event){
        // insert into the tmp map 
        __u32 scratch_key = 0;
        TrackFileChanges *blank_e = bpf_map_lookup_elem(&temp_pid_map, &scratch_key);
        if (!blank_e) {
            bpf_printk("(lsm/file_open)Failed to get temp_map\n");
            return 0; 
        }
        
        int update = bpf_map_update_elem(&active_file_pids, &pid, blank_e, BPF_ANY);
        if (update < 0) {
            bpf_printk("(lsm/file_open): Failed to insert pid %d. Ret: %d\n", pid, update);
            return 0;
        }

        // Relookup to get the valid per-CPU pointer 'e' (required by verifier)
        file_event = bpf_map_lookup_elem(&active_file_pids, &pid);
        if (!file_event) {
            bpf_printk("(lsm/file_open): Failed to get pointer after update for pid %d\n", pid);
            return 0;
        }
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 flags = BPF_CORE_READ(file, f_flags);
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    file_event->__generics.evt_type = EVENT_FILE_OPEN_AND_WRITE;
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->was_success = 0;
    // file_event->was_size_truncated = 0;
    file_event->was_file_modified = 0;
    file_event->do_not_update_atime = 0;
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    
    if ((flags & O_NOATIME) == O_NOATIME)
    {
        file_event->do_not_update_atime = 1;
    }
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    bpf_probe_read_kernel_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), name);
    bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), name);
    file_event->fptr = (__u64)file;
    file_event->has_emitted_read = 0;   
    file_event->has_emitted_write = 0; 

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));


    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    // file default
    file_event->new_mode = flags;
    file_event->mode = flags;
    file_event->old_uid = file_event->__generics.uid;
    file_event->new_uid = file_event->old_uid;
    file_event->old_gid = file_event->__generics.gid;
    file_event->new_gid = file_event->old_gid;
    // file_event->old_size = BPF_CORE_READ(file, f_inode->i_size);
    // file_event->new_size = BPF_CORE_READ(file, f_inode->i_size);

    file_event->old_atime =
        BPF_CORE_READ(file, f_inode->__i_atime.tv_nsec) +
        (BPF_CORE_READ(file, f_inode->__i_atime.tv_sec) * 1000000000ULL);

    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime =
        BPF_CORE_READ(file, f_inode->__i_mtime.tv_nsec) +
        (BPF_CORE_READ(file, f_inode->__i_mtime.tv_sec) * 1000000000ULL);

    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime =
        BPF_CORE_READ(file, f_inode->__i_ctime.tv_nsec) +
        (BPF_CORE_READ(file, f_inode->__i_ctime.tv_sec) * 1000000000ULL);

    file_event->new_ctime = file_event->old_ctime;
    
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();

    if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", 8);
        __builtin_memcpy(file_event->file_type_new, "REGULAR", 8);
    }
    else if ((mode & _S_IFMT) == _S_IFDIR)
    {
        __builtin_memcpy(file_event->file_type, "DIR", 4);
        __builtin_memcpy(file_event->file_type_new, "DIR", 4);
    }
    else if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK", 6);
        __builtin_memcpy(file_event->file_type_new, "BLOCK", 6);
    }
    else if ((mode & _S_IFMT) == _S_IFIFO)
    {
        __builtin_memcpy(file_event->file_type, "FIFO", 5);
        __builtin_memcpy(file_event->file_type_new, "FIFO", 5);
    }
    else if ((mode & _S_IFMT) == _S_IFLNK)
    {
        __builtin_memcpy(file_event->file_type, "LINK", 5);
        __builtin_memcpy(file_event->file_type_new, "LINK", 5);
    }
    else if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", 7);
        __builtin_memcpy(file_event->file_type_new, "SOCKET", 7);
    }
    else if ((mode & _S_IFMT) == _S_IFCHR)
    {
        __builtin_memcpy(file_event->file_type, "CHAR_DEVICE", 12);
        __builtin_memcpy(file_event->file_type_new, "CHAR_DEVICE", 12);
    }
    else
    {
        __builtin_memcpy(file_event->file_type, "UNKNOWN", 8);
        __builtin_memcpy(file_event->file_type_new, "UNKNOWN", 8);
    }

    /* Sensitive / suid / sgid / sticky / other flags */
    file_event->is_sensitive_file = -1;
    file_event->was_suid_changed = -1;
    file_event->suid_set = -1;
    file_event->suid_cleared = -1;
    file_event->was_sgid_changed = -1;
    file_event->sgid_set = -1;
    file_event->sgid_cleared = -1;
    file_event->was_sticky_changed = -1;
    file_event->sticky_set = -1;
    file_event->sticky_cleared = -1;

    file_event->was_permission_changed = -1;
    file_event->was_owner_changed = -1;
    file_event->was_group_changed = -1;
    // file_event->was_size_extended = -1;
    file_event->was_creation_time_changed = -1;
    file_event->was_access_time_changed = -1;
    file_event->was_modified_time_changed = -1;

    /* Inode/file creation indicators */
    file_event->was_file_created = -1;
    dev_t dev = BPF_CORE_READ(file,f_path.dentry, d_sb,s_dev);
    /* Device numbers */
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;
    file_event->inode_number = BPF_CORE_READ(file,f_path.dentry,d_inode,i_ino);
    file_event->inode_number_new = file_event->inode_number;
    /* Device numbers */
    dev_t rdev = BPF_CORE_READ(file, f_path.dentry,d_inode,i_rdev);
    file_event->rdev_minor = rdev >> 20;
    file_event->rdev_major = rdev & ((1 << 20) - 1);
    // file_event->i_bdev_major = -1;
    // file_event->i_bdev_minor = -1;
    // file_event->is_rdev_bdev_mismatch = -1;
    // file_event->is_rdev_bdev_mismatch_new = -1;

    file_event->is_target_dir_world_writable = -1;
    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

    
    file_event->is_symlink = -1;
    file_event->was_dir_removed = -1;
    file_event->is_current_dir_world_writable = -1;

    /* New inode device numbers (rename/move) */
    file_event->rdev_minor_new = -1;
    file_event->rdev_major_new = -1;
    // file_event->i_bdev_major_new = -1;
    // file_event->i_bdev_minor_new = -1;


    // bpf_ringbuf_submit(file_event, 0);
    return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr_u, struct dentry *dentry, struct iattr *iattr)
{

    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

     __u8 *is_pid_blocked = bpf_map_lookup_elem(&blocked_patterns_pids, &pid);
    if (is_pid_blocked) {
        return 0; 
    }

    char comm[TYPE];

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    // char isMatch = iterate(comm);
    // if (isMatch == 1)
    // {
    //     u8 temp = 1;
    //     int update = bpf_map_update_elem(&blocked_patterns_pids, &pid, &temp, BPF_ANY);
    //     if (update < 0) {
    //         bpf_printk("brbrFailed to update blocked_patterns_pids <pid %d >", pid);
    //     }else{
    //         bpf_printk("brbrSuccesfully blocked_patterns_pids <pid %d >", pid);
    //     }
    //     return 0;
    // }

    if (iterate(comm) == 1) {
        return block_pid_and_drop(pid);
    }

    char name[MAX_CHAR_LEN];
    bpf_core_read_str(name, sizeof(name), dentry->d_name.name);

    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, name);
    if (isFilenameBlocked != NULL)
    {
        bpf_printk("Blocked filename at inode_setattr_u << %s >> \n", name);
        return 0;
    }
    
    if (name[0] != '\0' && __builtin_strcmp(name, "trace_pipe") != 0)
    {
        if (iterate(name) == 1) {
            return block_pid_and_drop(pid);
        }
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_setattr) \n");
        return 0;
    }

    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    unsigned int valid = BPF_CORE_READ(iattr, ia_valid);

    file_event->__generics.evt_type = EVENT_INODE_SETATTR;
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->was_file_modified = 1;
  
    file_event->mode = BPF_CORE_READ(dentry, d_inode, i_mode);
    file_event->new_mode = BPF_CORE_READ(iattr, ia_mode);
    if (valid & ATTR_MODE)
    {
        file_event->was_permission_changed = 1;
    }
    else
    {
        file_event->was_permission_changed = 0;
    }
    // uid or guid changing
    // kuid_t and kgid_t => struct with val inside ???
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = BPF_CORE_READ(iattr, ia_uid).val;
    file_event->new_gid = BPF_CORE_READ(iattr, ia_gid).val;
    if (valid & ATTR_UID)
    {
        file_event->was_owner_changed = 1;
    }
    else
    {
        file_event->was_owner_changed = 0;
    }
    if (valid & ATTR_GID)
    {
        file_event->was_group_changed = 1;
    }
    else
    {
        file_event->was_group_changed = 0;
    }
    
    file_event->old_atime =
        BPF_CORE_READ(dentry, d_inode, __i_atime.tv_nsec) +
        (BPF_CORE_READ(dentry, d_inode, __i_atime.tv_sec) * 1000000000ULL);

    file_event->new_atime =
        BPF_CORE_READ(iattr, ia_atime.tv_nsec) +
        (BPF_CORE_READ(iattr, ia_atime.tv_sec) * 1000000000ULL);

    file_event->old_mtime =
        BPF_CORE_READ(dentry, d_inode, __i_mtime.tv_nsec) +
        (BPF_CORE_READ(dentry, d_inode, __i_mtime.tv_sec) * 1000000000ULL);

    file_event->new_mtime =
        BPF_CORE_READ(iattr, ia_mtime.tv_nsec) +
        (BPF_CORE_READ(iattr, ia_mtime.tv_sec) * 1000000000ULL);

    file_event->old_ctime =
        BPF_CORE_READ(dentry, d_inode, __i_ctime.tv_nsec) +
        (BPF_CORE_READ(dentry, d_inode, __i_ctime.tv_sec) * 1000000000ULL);

    file_event->new_ctime =
        BPF_CORE_READ(iattr, ia_ctime.tv_nsec) +
        (BPF_CORE_READ(iattr, ia_ctime.tv_sec) * 1000000000ULL);

    if (valid & ATTR_ATIME)
        file_event->was_access_time_changed = 1;
    else
        file_event->was_access_time_changed = 0;

    if (valid & ATTR_MTIME)
        file_event->was_modified_time_changed = 1;
    else
        file_event->was_modified_time_changed = 0;

    if (valid & ATTR_CTIME)
        file_event->was_creation_time_changed = 1;
    else
        file_event->was_creation_time_changed = 0;
   
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
 
    bpf_probe_read_kernel_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), name);
    bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), name);
   
    file_event->suid_set = !(file_event->mode & _S_ISUID) && (file_event->new_mode & _S_ISUID);
    file_event->suid_cleared = (file_event->mode & _S_ISUID) && !(file_event->new_mode & _S_ISUID);
    file_event->was_suid_changed = file_event->suid_set || file_event->suid_cleared;

    file_event->sgid_set = !(file_event->mode & _S_ISGID) && (file_event->new_mode & _S_ISGID);
    file_event->sgid_cleared = (file_event->mode & _S_ISGID) && !(file_event->new_mode & _S_ISGID);
    file_event->was_sgid_changed = file_event->sgid_set || file_event->sgid_cleared;


    file_event->was_sticky_changed =
        ((file_event->mode & _S_ISVTX) != (file_event->new_mode & _S_ISVTX));

    file_event->sticky_set =
        (!(file_event->mode & _S_ISVTX) && (file_event->new_mode & _S_ISVTX));

    file_event->sticky_cleared =
        ((file_event->mode & _S_ISVTX) && !(file_event->new_mode & _S_ISVTX));

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
   
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));


    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    __u16 mode = BPF_CORE_READ(dentry, d_inode->i_mode);
    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }
    else if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", sizeof("REGULAR"));
        __builtin_memcpy(file_event->file_type_new, "REGULAR", sizeof("REGULAR"));
    }
    else if ((mode & _S_IFMT) == _S_IFDIR)
    {
        __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
        __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    }
    else if ((mode & _S_IFMT) == _S_IFIFO)
    {
        __builtin_memcpy(file_event->file_type, "FIFO", sizeof("FIFO"));
        __builtin_memcpy(file_event->file_type_new, "FIFO", sizeof("FIFO"));
    }
    else if ((mode & _S_IFMT) == _S_IFLNK)
    {
        __builtin_memcpy(file_event->file_type, "SYMLINK", sizeof("SYMLINK"));
        __builtin_memcpy(file_event->file_type_new, "SYMLINK", sizeof("SYMLINK"));
    }
    else if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
    }
    else if ((mode & _S_IFMT) == _S_IFCHR)
    {
        __builtin_memcpy(file_event->file_type, "CHAR_DEVICE", sizeof("CHAR_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "CHAR_DEVICE", sizeof("CHAR_DEVICE"));
    }
    else
    {
        __builtin_memcpy(file_event->file_type, "UNKNOWN", sizeof("UNKNOWN"));
        __builtin_memcpy(file_event->file_type_new, "UNKNOWN", sizeof("UNKNOWN"));
    }

    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    dev_t dev = BPF_CORE_READ(dentry, d_sb,s_dev);

    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;
    dev_t rdev = BPF_CORE_READ(dentry, d_inode, i_rdev);
    file_event->rdev_minor = rdev >> 20;
    file_event->rdev_major = rdev & ((1 << 20) - 1);
    file_event->inode_number = BPF_CORE_READ(dentry, d_inode,i_ino);
   
    file_event->is_target_dir_world_writable = -1;
    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

   
    file_event->is_symlink = -1;
    file_event->was_dir_removed = -1;
    file_event->is_current_dir_world_writable = -1;

    file_event->rdev_minor_new = -1;
    file_event->rdev_major_new = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;

}

SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *inode, struct dentry *dentry, umode_t mode)
{
    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    if ((mode & _S_IFMT) == _S_IFCHR)
    {
        return 0;
    }

    char name[MAX_CHAR_LEN];
    bpf_core_read_str(name, sizeof(name), dentry->d_name.name);

    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, name);
    if (isFilenameBlocked != NULL)
    {
        bpf_printk("Blocked filename at inode_create << %s >> \n", name);
        return 0;
    }

    char isMatch = iterate(name);
    if (isMatch == 1)
    {
        return 0;
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_create) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    file_event->__generics.evt_type = EVENT_INODE_CREATE;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    bpf_probe_read_kernel_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), name);
    bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), name);

    file_event->was_file_created = 1;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = file_event->old_uid;
    file_event->new_gid = file_event->old_gid;
    file_event->was_file_modified = -1;
    file_event->new_mode = mode;
    file_event->mode = mode;

    

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};


    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;

    dev_t rdev = BPF_CORE_READ(inode, i_rdev);
    __u32 rdev_major = rdev >> 20;
    __u32 rdev_minor = rdev & ((1 << 20) - 1);
    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->inode_number = BPF_CORE_READ(dentry, d_inode,i_ino);
    file_event->rdev_major = rdev_major;
    file_event->rdev_minor = rdev_minor;

    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }

    if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", sizeof("REGULAR"));
        __builtin_memcpy(file_event->file_type_new, "REGULAR", sizeof("REGULAR"));
    }

    if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
    }

    file_event->rdev_minor_new = file_event->rdev_minor;
    file_event->rdev_major_new = file_event->rdev_major;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
  
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));

    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_target_dir_world_writable = -1;
    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

   
    file_event->is_symlink = -1;
    file_event->was_dir_removed = -1;
    file_event->is_current_dir_world_writable = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(inode_link, struct dentry *dentry, struct inode *inode, struct dentry *dentry_new)
{
    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    __u16 mode = BPF_CORE_READ(inode, i_mode);

    if ((mode & _S_IFMT) == _S_IFCHR)
    {
        return 0;
    }

    char name[MAX_CHAR_LEN];
    bpf_core_read_str(name, sizeof(name), dentry->d_name.name);

    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, name);
    if (isFilenameBlocked != NULL)
    {
        bpf_printk("Blocked filename at inode_link << %s >> \n", name);
        return 0;
    }


    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_link) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    file_event->__generics.evt_type = EVENT_INODE_LINK;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    bpf_probe_read_kernel_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), name);
    bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), name);
    file_event->was_file_created = 1;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val; 
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;

    file_event->new_uid = BPF_CORE_READ(dentry_new, d_inode, i_uid).val; 
    file_event->new_gid = BPF_CORE_READ(dentry_new, d_inode, i_uid).val; 
    file_event->was_file_modified = -1;
    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;

    dev_t rdev = BPF_CORE_READ(inode, i_rdev);
    __u32 rdev_major = rdev >> 20;
    __u32 rdev_minor = rdev & ((1 << 20) - 1);
    // old dev 
    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;
    file_event->inode_number = BPF_CORE_READ(dentry, d_inode,i_ino);
    file_event->rdev_major = rdev_major;
    file_event->rdev_minor = rdev_minor;

    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }
    if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", sizeof("REGULAR"));
        __builtin_memcpy(file_event->file_type_new, "REGULAR", sizeof("REGULAR"));
    }
    if ((mode & _S_IFMT) == _S_IFDIR)
    {
        __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
        __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    }

    if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
    }

    file_event->rdev_minor_new = file_event->rdev_minor;
    file_event->rdev_major_new = file_event->rdev_major;

    const char unsigned *new_filename = BPF_CORE_READ(dentry_new, d_name.name);
    bpf_core_read_str(file_event->new_filename, sizeof(file_event->new_filename), new_filename);

    // CHECK IF THE TARGET DIR IS WORLD-WRITABLE
    struct inode *target_dir_inode = BPF_CORE_READ(dentry_new, d_parent, d_inode);
    umode_t dir_mode = BPF_CORE_READ(target_dir_inode, i_mode);
    file_event->is_target_dir_world_writable = (dir_mode & _S_IWOTH) ? 1 : 0;

    // CHECK IF ITS SGID OR SUID BINARY
    umode_t src_mode = BPF_CORE_READ(dentry, d_inode, i_mode);
    file_event->is_linked_file_SGID_or_SUID =
        ((src_mode & _S_ISUID) || (src_mode & _S_ISGID)) ? 1 : 0;

    // CHECK THE UID OF THE FILE BEING LINKED IS THE SAME AS THE TARGER DIR
    kuid_t src_uid = BPF_CORE_READ(dentry, d_inode, i_uid);
    kuid_t tgt_uid = BPF_CORE_READ(dentry_new, d_inode, i_uid);

    file_event->is_cross_user_link = (src_uid.val != tgt_uid.val) ? 1 : 0;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;

    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_symlink = -1;
    file_event->was_dir_removed = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

// INODE_SYMLINK
//**************** */

SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *inode, struct dentry *dentry, const char *symlink_path)
{
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    __u16 mode = BPF_CORE_READ(inode, i_mode);

    if ((mode & _S_IFMT) == _S_IFCHR)
    {
        return 0;
    }

    char symlink_path_local[MAX_CHAR_LEN];
    bpf_core_read_str(symlink_path_local, sizeof(symlink_path_local), symlink_path);
    __u8 *isFilenameBlocked = bpf_map_lookup_elem(&blocked_filenames, symlink_path_local);
    if (isFilenameBlocked != NULL)
    {

        bpf_printk("Blocked filename at inode_symlink << %s >> \n", symlink_path_local);
        return 0;
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_symlink) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    

    file_event->__generics.evt_type = EVENT_INODE_SYMLINK;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);

    file_event->was_file_created = 1;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = file_event->old_uid;
    file_event->new_gid = file_event->old_gid;
    file_event->was_file_modified = -1;
    

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;

    dev_t rdev = BPF_CORE_READ(inode, i_rdev);
    __u32 rdev_major = rdev >> 20;
    __u32 rdev_minor = rdev & ((1 << 20) - 1);
    file_event->rdev_major = rdev_major;
    file_event->rdev_minor = rdev_minor;
    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;
    file_event->inode_number = BPF_CORE_READ(dentry, d_inode,i_ino);



    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }

    if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", sizeof("REGULAR"));
        __builtin_memcpy(file_event->file_type_new, "REGULAR", sizeof("REGULAR"));
    }
    if ((mode & _S_IFMT) == _S_IFDIR)
    {
        __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
        __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    }

    if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
    }

    file_event->rdev_minor_new = file_event->rdev_minor;
    file_event->rdev_major_new = file_event->rdev_major;

    bpf_core_read_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), symlink_path);
    const char unsigned *new_filename = BPF_CORE_READ(dentry, d_name.name);
    bpf_core_read_str(file_event->new_filename, sizeof(file_event->new_filename), new_filename);

    // CHECK IF THE TARGET DIR IS WORLD-WRITABLE
    umode_t dir_mode = BPF_CORE_READ(inode, i_mode);
    file_event->is_target_dir_world_writable = (dir_mode & _S_IWOTH) ? 1 : 0;

    // CHECK IF ITS SGID OR SUID BINARY
    umode_t src_mode = BPF_CORE_READ(dentry, d_inode, i_mode);
    file_event->is_linked_file_SGID_or_SUID =
        ((src_mode & _S_ISUID) || (src_mode & _S_ISGID)) ? 1 : 0;

    file_event->is_cross_user_link = -1;
    file_event->is_symlink = (mode & _S_IFLNK) == _S_IFLNK ? 1 : 0;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_to_sensitive_file = -1;

    
    file_event->was_dir_removed = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}
/*INODE_MKDIR*/
/*************** */

SEC("lsm/inode_mkdir")
int BPF_PROG(inode_mkdir, struct inode *inode, struct dentry *dentry, umode_t mode)
{
    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_mkdir) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    

    file_event->__generics.evt_type = EVENT_INODE_MKDIR;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    // command
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    // filename
    bpf_core_read_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), dentry->d_name.name);
    bpf_core_read_str(file_event->new_filename, sizeof(file_event->new_filename), dentry->d_name.name);

    file_event->was_file_created = 1;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = file_event->old_uid;
    file_event->new_gid = file_event->old_gid;
    file_event->was_file_modified = -1;

    file_event->new_mode = mode;
    file_event->mode = mode;

    

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;
    __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
    __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    file_event->inode_number = BPF_CORE_READ(dentry, d_inode,i_ino);
    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

    
    file_event->is_symlink = -1;
    file_event->was_dir_removed = 0;
    umode_t dir_mode = BPF_CORE_READ(inode, i_mode);
    file_event->is_target_dir_world_writable = -1;
    file_event->is_current_dir_world_writable = (dir_mode & _S_IWOTH) ? 1 : 0;
    dev_t rdev = BPF_CORE_READ(inode,i_rdev);
    file_event->rdev_minor = rdev >> 20;
    file_event->rdev_major = rdev & ((1 << 20) - 1);
    file_event->rdev_major_new = file_event->rdev_major;
    file_event->rdev_minor_new = file_event->rdev_minor;
    // file_event->i_bdev_major = -1;
    // file_event->i_bdev_minor = -1;
    // file_event->i_bdev_major_new = -1;
    // file_event->i_bdev_minor_new = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

/*INODE_RMDIR*/
/***************** */
/***************** */
/***************** */
/***************** */

SEC("lsm/inode_rmdir")
int BPF_PROG(inode_rmdir_func, struct inode *inode, struct dentry *dentry)
{
    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_rmdir) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    

    file_event->__generics.evt_type = EVENT_INODE_RMDIR;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    // command
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    // filename
    bpf_core_read_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), dentry->d_name.name);
    bpf_core_read_str(file_event->new_filename, sizeof(file_event->new_filename), dentry->d_name.name);
    file_event->was_file_created = 0;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = file_event->old_uid;
    file_event->new_gid = file_event->old_gid;
    file_event->was_file_modified = -1;
    file_event->new_mode = -1;
    file_event->mode = -1;

    

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;
    __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
    __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    file_event->was_dir_removed = 1;
    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

    
    file_event->is_symlink = -1;
    file_event->is_target_dir_world_writable = -1;
    file_event->is_current_dir_world_writable = -1;
    
    dev_t rdev = BPF_CORE_READ(inode,i_rdev);
    file_event->rdev_minor = rdev >> 20;
    file_event->rdev_major = rdev & ((1 << 20) - 1);
    file_event->rdev_major_new = file_event->rdev_major;
    file_event->rdev_minor_new = file_event->rdev_minor;
    // file_event->i_bdev_major = -1;
    // file_event->i_bdev_minor = -1;
    // file_event->i_bdev_major_new = -1;
    // file_event->i_bdev_minor_new = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

SEC("lsm/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *inode, struct dentry *dentry, umode_t mode, dev_t device)
{

    const char unsigned *filename = BPF_CORE_READ(dentry, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    if ((mode & _S_IFMT) == _S_IFCHR)
    {
        return 0;
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_mknod) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    

    file_event->__generics.evt_type = EVENT_INODE_MKNOD;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    // command
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);
    // filename
    bpf_core_read_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), dentry->d_name.name);
    bpf_core_read_str(file_event->new_filename, sizeof(file_event->new_filename), dentry->d_name.name);

    file_event->was_file_created = 1;
    file_event->old_uid = BPF_CORE_READ(dentry, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(dentry, d_inode, i_gid).val;
    file_event->new_uid = file_event->old_uid;
    file_event->new_gid = file_event->old_gid;
    file_event->was_file_modified = -1;
    file_event->new_mode = mode;
    file_event->mode = mode;

    

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &dentry->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &dentry->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &dentry->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;

    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }

    if ((mode & _S_IFMT) == _S_IFIFO)
    {
        // bpf_core_read_user_str(file_event->file_type, sizeof(file_event->file_type), "FIFO");
        __builtin_memcpy(file_event->file_type, "FIFO", sizeof("FIFO"));
        __builtin_memcpy(file_event->file_type_new, "FIFO", sizeof("FIFO"));
    }

    dev_t dev = BPF_CORE_READ(dentry, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    file_event->dev_major_new = file_event->dev_major;
    file_event->dev_minor_new = file_event->dev_minor;

    __u32 rdev_major = device >> 20;
    __u32 rdev_minor = device & ((1 << 20) - 1);
    file_event->rdev_major = rdev_major;
    file_event->rdev_minor = rdev_minor;

    if ((mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));

    }

    file_event->rdev_major_new = rdev_major;
    file_event->rdev_minor_new = rdev_minor;

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;
    __builtin_memcpy(file_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(file_event->__auth.login_type, "void", sizeof("void"));
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

    
    file_event->is_symlink = -1;
    file_event->is_target_dir_world_writable = -1;
    umode_t dir_mode = BPF_CORE_READ(inode, i_mode);
    file_event->is_current_dir_world_writable = (dir_mode & _S_IWOTH) ? 1 : 0;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_inode, struct dentry *old_dir, struct inode *new_inode, struct dentry *new_dir)
{

    const char unsigned *filename = BPF_CORE_READ(old_dir, d_name.name);
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid)
    {
        if (*my_pid == pid || *my_pid == ppid)
        {
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

    bpf_get_current_comm(comm, sizeof(comm));
    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked != NULL)
    {
        return 0;
    }

    TrackFileChanges *file_event = bpf_ringbuf_reserve(&file_events, sizeof(*file_event), 0);
    if (!file_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for file event (lsm/inode_rename) \n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    

    file_event->__generics.evt_type = EVENT_INODE_RENAME;
    file_event->comm_timestamp = bpf_ktime_get_tai_ns();
    file_event->__generics.pid = pid;
    file_event->__generics.ppid = realPPID;
    file_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    file_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    file_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    file_event->was_success = 0;
    if (file_event->__generics.exit_code >= 0)
    {
        file_event->was_success = 1;
    }
    // command
    bpf_probe_read_kernel_str(file_event->__generics.comm, sizeof(file_event->__generics.comm), comm);

    // new filename

    __builtin_memset(file_event->new_filename, 0, sizeof(file_event->new_filename));
    const unsigned char *new_filename_ptr = BPF_CORE_READ(new_dir, d_name.name);

   
    if (new_filename_ptr) {
      
        long ret = bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), new_filename_ptr);
        bpf_printk("KERNEL RENAME HOOK: %s\n", file_event->new_filename);
        if (ret < 0) {
            char fallback[] = "read_failed";
            __builtin_memcpy(file_event->new_filename, fallback, sizeof(fallback));
        }
    } else {
        char null_fallback[] = "null_ptr";
        __builtin_memcpy(file_event->new_filename, null_fallback, sizeof(null_fallback));
    }

    // const char unsigned *new_filename = BPF_CORE_READ(new_dir, d_name.name);
    // bpf_probe_read_kernel_str(file_event->new_filename, sizeof(file_event->new_filename), new_filename);

    

    // // 1. Extragem pointer-ul către nume și lungimea exactă a acestuia
    // const char unsigned *new_filename_ptr = BPF_CORE_READ(new_dir, d_name.name);
    // __u32 new_name_len = BPF_CORE_READ(new_dir, d_name.len);

    // // 2. Ne asigurăm că lungimea nu depășește dimensiunea buffer-ului nostru din inel (ringbuf)
    // // Lăsăm 1 byte liber pentru terminatorul de string (\0)
    // if (new_name_len >= sizeof(file_event->new_filename)) {
    //     new_name_len = sizeof(file_event->new_filename) - 1;
    // }

    // // 3. Folosim bpf_probe_read_kernel (fără _str) pentru a citi EXACT acei bytes, niciunul în plus
    // bpf_probe_read_kernel(file_event->new_filename, new_name_len, new_filename_ptr);

    // // 4. Adăugăm manual terminatorul de string pentru a fi perfect lizibil în user-space (C/Python)
    // file_event->new_filename[new_name_len] = '\0';

    // filename (old filename)
    bpf_core_read_str(file_event->__generics.filename, sizeof(file_event->__generics.filename), filename);
    file_event->was_file_created = 1;
    // old dir uid and gid
    file_event->old_uid = BPF_CORE_READ(old_dir, d_inode, i_uid).val;
    file_event->old_gid = BPF_CORE_READ(old_dir, d_inode, i_gid).val;
    // new dir uid and gid
    file_event->new_uid = BPF_CORE_READ(new_dir, d_inode, i_uid).val;
    file_event->new_gid = BPF_CORE_READ(new_dir, d_inode, i_gid).val;
    file_event->was_file_modified = -1;

    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(file_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // old dir permissions
    __u16 mode = BPF_CORE_READ(old_inode, i_mode);
    file_event->mode = mode;
    if ((mode & _S_IWOTH) == _S_IWOTH)
    {
        file_event->is_current_dir_world_writable = 1;
    }
    else
    {
        file_event->is_current_dir_world_writable = 0;
    }
    // new location dir permission

    /*for the new location*/
    __u16 new_mode = BPF_CORE_READ(new_inode, i_mode);
    file_event->new_mode = mode;

    file_event->was_sticky_changed = 0;
    file_event->sticky_cleared = 0;

    if ((new_mode & _S_ISVTX) == _S_ISVTX)
    {
        file_event->sticky_set = 1;
    }
    else
    {
        file_event->sticky_set = 0;
    }

    if ((new_mode & _S_IWOTH) == _S_IWOTH)
    {
        file_event->is_target_dir_world_writable = 1;
    }
    else
    {
        file_event->is_target_dir_world_writable = 0;
    }

    file_event->was_suid_changed = 0;
    file_event->suid_cleared = 0;

    if ((new_mode & _S_ISUID) == _S_ISUID)
    {
        file_event->suid_set = 1;
    }
    else
    {
        file_event->suid_set = 0;
    }

    file_event->was_sgid_changed = 0;
    file_event->sgid_cleared = 0;

    if ((new_mode & _S_ISGID) == _S_ISGID)
    {
        file_event->sgid_set = 1;
    }
    else
    {
        file_event->sgid_set = 0;
    }
    /*for the new location*/

    
    // de verificat pe user_space
    file_event->is_sensitive_file = -1;

    struct timespec64 old_atime = {};
    struct timespec64 old_mtime = {};
    struct timespec64 old_ctime = {};

    bpf_core_read(&old_atime, sizeof(old_atime), &old_dir->d_inode->__i_atime);
    bpf_core_read(&old_mtime, sizeof(old_mtime), &old_dir->d_inode->__i_mtime);
    bpf_core_read(&old_ctime, sizeof(old_ctime), &old_dir->d_inode->__i_ctime);

    file_event->old_atime = old_atime.tv_nsec + (old_atime.tv_sec * 1000000000ULL);
    file_event->new_atime = file_event->old_atime;

    file_event->old_mtime = old_mtime.tv_nsec + (old_mtime.tv_sec * 1000000000ULL);
    file_event->new_mtime = file_event->old_mtime;

    file_event->old_ctime = old_ctime.tv_nsec + (old_ctime.tv_sec * 1000000000ULL);
    file_event->new_ctime = file_event->old_ctime;

    if ((mode & _S_IFMT) == _S_IFSOCK)
    {
        __builtin_memcpy(file_event->file_type, "SOCKET", sizeof("SOCKET"));
        __builtin_memcpy(file_event->file_type_new, "SOCKET", sizeof("SOCKET"));
    }

    if ((mode & _S_IFMT) == _S_IFIFO)
    {
        // bpf_core_read_user_str(file_event->file_type, sizeof(file_event->file_type), "FIFO");
        __builtin_memcpy(file_event->file_type, "FIFO", sizeof("FIFO"));
        __builtin_memcpy(file_event->file_type_new, "FIFO", sizeof("FIFO"));
    }

    if ((mode & _S_IFMT) == _S_IFREG)
    {
        __builtin_memcpy(file_event->file_type, "REGULAR", sizeof("REGULAR"));
        __builtin_memcpy(file_event->file_type_new, "REGULAR", sizeof("REGULAR"));
    }

    if ((mode & _S_IFMT) == _S_IFDIR)
    {
        __builtin_memcpy(file_event->file_type, "DIR", sizeof("DIR"));
        __builtin_memcpy(file_event->file_type_new, "DIR", sizeof("DIR"));
    }

    // verifica daca plecam dintr-o locatie securizata spre una nesecurizata
    // vertifica daca plecam dintr-o locatie nesecurizata spre una securizata
    // verificam ce fisier se muta acolo
    // daca e un fisier sensibil care este mutat

    // OLD DEV
    dev_t dev = BPF_CORE_READ(old_dir, d_sb, s_dev);
    file_event->dev_major = dev >> 20;
    file_event->dev_minor = dev & ((1 << 20) - 1);
    dev_t new_dev = BPF_CORE_READ(new_dir, d_sb, s_dev);
    file_event->dev_major_new = new_dev >> 20;
    file_event->dev_minor_new = new_dev & ((1 << 20) - 1);

    // OLD RDEV
    dev_t rdev = BPF_CORE_READ(old_inode, i_rdev);
    __u32 rdev_major = rdev >> 20;
    __u32 rdev_minor = rdev & ((1 << 20) - 1);
    file_event->rdev_major = rdev_major;
    file_event->rdev_minor = rdev_minor;

    // NEW RDEV
    dev_t rdev_new = BPF_CORE_READ(new_inode, i_rdev);
    __u32 rdev_major_new = rdev_new >> 20;
    __u32 rdev_minor_new = rdev_new & ((1 << 20) - 1);
    file_event->rdev_minor_new = rdev_minor_new;
    file_event->rdev_minor_new = rdev_minor_new;

    // old bdev
    if ((mode & _S_IFMT) == _S_IFBLK)
    {

        __builtin_memcpy(file_event->file_type, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));

    }

    // new bdev
    if ((new_mode & _S_IFMT) == _S_IFBLK)
    {
        __builtin_memcpy(file_event->file_type_new, "BLOCK_DEVICE", sizeof("BLOCK_DEVICE"));

    }
    file_event->inode_number = BPF_CORE_READ(old_dir,d_inode,i_ino);
    file_event->inode_number_new = BPF_CORE_READ(new_dir,d_inode,i_ino);

    file_event->__auth.is_success = -1;
    file_event->__auth.is_switching_user = -1;
    file_event->__auth.is_switching_root = -1;
    file_event->__auth.is_changing_password = -1;
    file_event->__auth.is_root_command = -1;

    
    file_event->__sock.protocol_family = -1;
    file_event->__sock.socket_type = -1;
    file_event->__sock.protocol = -1;
    file_event->__sock.is_important_port = -1;
    file_event->__sock.port = -1;
    file_event->__sock.ipv4 = -1;
    file_event->__sock.local_ipv4_socket_addr = -1;
    file_event->__sock.local_socket_port = -1;
    file_event->__sock.peer_pid = -1;
    file_event->__sock.peer_uid = -1;
    file_event->__sock.peer_gid = -1;
    file_event->__sock.backlog_value = -1;
    file_event->__sock.ifindex = -1;
    file_event->__sock.kernel_sock = -1;
    file_event->__sock.is_success = -1;
    __builtin_memcpy(file_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.ipv6, "void", sizeof("void"));
    __builtin_memcpy(file_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));

    file_event->is_linked_file_SGID_or_SUID = -1;
    file_event->is_linked_to_sensitive_file = -1;
    file_event->is_cross_user_link = -1;

    
    file_event->is_symlink = -1;
    file_event->do_not_update_atime = -1;

    bpf_ringbuf_submit(file_event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
