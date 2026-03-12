#include "../vmlinux/vmlinux.h"
#include "socket.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
    __uint(max_entries, 4096 * 512 * 32); // 8mb
} file_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TYPE]);
    __type(value, __u8);
} comm_filtering SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TYPE]);
    __type(value, __u8);
} socket_comm_filtering SEC(".maps");


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

static char iterate(const char *str)
{
    struct iterate_ctx ctx = {};
    // __builtin_memset(&ctx, 0, sizeof(ctx));
    ctx.match_found = 0;
    ctx.filename = str;
    bpf_loop(LITTLE_MAP_SIZE, iterate_cb, &ctx, 0);
    return ctx.match_found;
}


SEC("lsm/socket_create")
int BPF_PROG(socket_create, int protocol_family, int socket_type, int protocol, int kernel)
{
    __u32 key = 0;
    __u32 *my_pid;

    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked){
        return 0;
    }
    __u8 *isCommSocketBlocked = bpf_map_lookup_elem(&socket_comm_filtering, comm);

    if (isCommSocketBlocked){
        return 0;
    }

    char isMatch = iterate(comm);
    if (isMatch == 1)
    {
        return 0;
    }


    if (kernel == 1)
    {
        // skipping internal socket creation by kernel
        return 0;
    }

    TrackFileChanges *sock_create_evt = bpf_ringbuf_reserve(&file_events, sizeof(*sock_create_evt), 0);
    if (!sock_create_evt)
    {
        bpf_printk("bpf_ringbuf_reserve failed for socket create event\n");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    sock_create_evt->__generics.evt_type = EVENT_SOCKET_CREATION;
    sock_create_evt->__generics.pid = pid;
    sock_create_evt->__generics.ppid = realPPID;
    sock_create_evt->__generics.uid = (__u32)bpf_get_current_uid_gid();
    sock_create_evt->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    sock_create_evt->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(sock_create_evt->__generics.comm, sizeof(sock_create_evt->__generics.comm), comm);
    sock_create_evt->comm_timestamp = bpf_ktime_get_tai_ns();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    sock_create_evt->__generics.duration_ns = bpf_ktime_get_ns() - start_time;

    sock_create_evt->__sock.protocol_family = protocol_family;
    sock_create_evt->__sock.socket_type = socket_type;
    sock_create_evt->__sock.protocol = protocol;
    sock_create_evt->__sock.kernel_sock = kernel;
    sock_create_evt->__sock.protocol_family = protocol_family;
    sock_create_evt->__sock.is_success = 0;
    if (sock_create_evt->__generics.exit_code >= 0)
    {
        sock_create_evt->__sock.is_success = 1;
    }

    __builtin_memcpy(sock_create_evt->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->new_filename, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->file_type, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->file_type_new, "void", sizeof("void"));

    // ─────────────────────────────
    // 🔐 AUTH SECTION DEFAULTS
    // ─────────────────────────────
    sock_create_evt->__auth.is_success = -1;
    sock_create_evt->__auth.is_switching_user = -1;
    sock_create_evt->__auth.is_switching_root = -1;
    sock_create_evt->__auth.is_changing_password = -1;
    sock_create_evt->__auth.is_root_command = -1;
    __builtin_memcpy(sock_create_evt->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->__auth.login_type, "void", sizeof("void"));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(sock_create_evt->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // ─────────────────────────────
    // 🌐 SOCKET SECTION DEFAULTS
    // ─────────────────────────────
    sock_create_evt->__sock.is_important_port = -1;
    sock_create_evt->__sock.port = -1;
    sock_create_evt->__sock.ipv4 = -1;
    sock_create_evt->__sock.local_ipv4_socket_addr = -1;
    sock_create_evt->__sock.local_socket_port = -1;
    sock_create_evt->__sock.peer_pid = -1;
    sock_create_evt->__sock.peer_uid = -1;
    sock_create_evt->__sock.peer_gid = -1;
    sock_create_evt->__sock.backlog_value = -1;
    sock_create_evt->__sock.ifindex = -1;
    __builtin_memcpy(sock_create_evt->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(sock_create_evt->__sock.path, "void", sizeof("void"));

    // ─────────────────────────────
    // 📂 FILE SECTION DEFAULTS
    // ─────────────────────────────
    sock_create_evt->mode = 0;
    sock_create_evt->new_mode = 0;
    sock_create_evt->old_uid = sock_create_evt->__generics.uid;
    sock_create_evt->new_uid = sock_create_evt->old_uid;
    sock_create_evt->old_gid = sock_create_evt->__generics.gid;
    sock_create_evt->new_gid = sock_create_evt->old_gid;

    // sock_create_evt->old_size = -1;
    // sock_create_evt->new_size = -1;

    sock_create_evt->was_permission_changed = 0;
    sock_create_evt->was_owner_changed = 0;
    sock_create_evt->was_group_changed = 0;
    // sock_create_evt->was_size_extended = 0;
    sock_create_evt->was_creation_time_changed = 0;
    sock_create_evt->was_access_time_changed = 1; // writing updates atime
    sock_create_evt->was_modified_time_changed = 0;

    // file timestamps (approximate)
    sock_create_evt->old_atime = -1;
    sock_create_evt->new_atime = -1;
    sock_create_evt->old_mtime = -1;
    sock_create_evt->new_mtime = -1;
    sock_create_evt->old_ctime = -1;
    sock_create_evt->new_ctime = -1;

    // sensitive bits / metadata
    sock_create_evt->is_sensitive_file = -1;
    sock_create_evt->was_suid_changed = -1;
    sock_create_evt->was_sgid_changed = -1;
    sock_create_evt->was_sticky_changed = -1;

    // dev + link info
    sock_create_evt->dev_major = -1;
    sock_create_evt->dev_minor = -1;
    sock_create_evt->dev_major_new = -1;
    sock_create_evt->dev_minor_new = -1;
    sock_create_evt->rdev_major = -1;
    sock_create_evt->rdev_minor = -1;
    // sock_create_evt->i_bdev_major = -1;
    // sock_create_evt->i_bdev_minor = -1;
    sock_create_evt->rdev_major_new = -1;
    sock_create_evt->rdev_minor_new = -1;
    // sock_create_evt->i_bdev_major_new = -1;
    // sock_create_evt->i_bdev_minor_new = -1;

    sock_create_evt->is_symlink = -1;
    sock_create_evt->was_file_created = -1;
    sock_create_evt->was_dir_removed = -1;

    bpf_ringbuf_submit(sock_create_evt, 0);
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *addr, int addrlen)
{

    __u32 *my_pid;
    __u32 key = 0;
    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

   __u32 ppid = (__u32)pid_tgid;

    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked){
        return 0;
    }

    __u8 *isCommSocketBlocked = bpf_map_lookup_elem(&socket_comm_filtering, comm);
    if (isCommSocketBlocked){
        return 0;
    }
    
    char isMatch = iterate(comm);
    if (isMatch == 1)
    {
        return 0;
    }



    TrackFileChanges *sock_bind_evt = bpf_ringbuf_reserve(&file_events, sizeof(*sock_bind_evt), 0);
    if (!sock_bind_evt)
    {
        bpf_printk("bpf_ringbuf_reserve failed for socket create event\n");
        return 0;
    }
    
    struct sock *sk = BPF_CORE_READ(sock, sk);
    u8 kern_sock = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock);
    sock_bind_evt->__sock.kernel_sock = kern_sock;
    // bpf_probe_read_kernel(&sock_bind_evt->__sock.kernel_sock, sizeof(sock_bind_evt->__sock.kernel_sock), &sk->sk_kern_sock);
    if (sock_bind_evt->__sock.kernel_sock == 1)
    {
        bpf_ringbuf_discard(sock_bind_evt,0);
        return 0;
    }

   
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);
    
    __builtin_memcpy(sock_bind_evt->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->new_filename, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->file_type, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->file_type_new, "void", sizeof("void"));

    sock_bind_evt->__generics.evt_type = EVENT_SOCKET_BIND;
    sock_bind_evt->__generics.pid = pid;
    sock_bind_evt->__generics.ppid = realPPID;
    sock_bind_evt->__generics.uid = (__u32)bpf_get_current_uid_gid();
    sock_bind_evt->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    sock_bind_evt->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(sock_bind_evt->__generics.comm, sizeof(sock_bind_evt->__generics.comm), comm);
    sock_bind_evt->__sock.is_important_port = 0;
    sock_bind_evt->__sock.is_success = 0;
    if (sock_bind_evt->__generics.exit_code >= 0)
    {
        sock_bind_evt->__sock.is_success = 1;
    }
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    sock_bind_evt->__generics.duration_ns = bpf_ktime_get_ns() - start_time;
    sock_bind_evt->comm_timestamp = bpf_ktime_get_tai_ns();

    __u16 type = BPF_CORE_READ(sk, sk_type);         // The SOCK_STREAM, SOCK_DGRAM value
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol); // The IPPROTO_TCP, IPPROTO_UDP value

    // sa_family
    sa_family_t family = BPF_CORE_READ(addr, sa_family);

    sock_bind_evt->__sock.protocol_family = family;
    sock_bind_evt->__sock.socket_type = type;
    sock_bind_evt->__sock.protocol = protocol;
    sock_bind_evt->__sock.ifindex = -1;
    sock_bind_evt->__sock.kernel_sock = 0;
    sock_bind_evt->__sock.peer_pid = -1;
    sock_bind_evt->__sock.peer_uid = -1;
    sock_bind_evt->__sock.peer_gid = -1;
    sock_bind_evt->__sock.local_ipv4_socket_addr = -1;
    sock_bind_evt->__sock.local_socket_port = -1;
    __builtin_memcpy(sock_bind_evt->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->__sock.path, "void", sizeof("void"));

    if (family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        unsigned short port = BPF_CORE_READ(sin, sin_port);
        // unsigned int ip = bpf_ntohl(BPF_CORE_READ(sin, sin_addr.s_addr));
        unsigned int ip = BPF_CORE_READ(sin, sin_addr.s_addr);


        // converting from network byte order to host byte order
        unsigned short host_port = bpf_ntohs(port);

        if (host_port > 0 && host_port < 1024)
        {
            sock_bind_evt->__sock.is_important_port = 1;
        }

        sock_bind_evt->__sock.port = host_port;
        sock_bind_evt->__sock.ipv4 = ip;
    }
    else if (family == AF_INET6)
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        unsigned short port = BPF_CORE_READ(sin6, sin6_port);
        bpf_probe_read_kernel(
            sock_bind_evt->__sock.ipv6,
            sizeof(sock_bind_evt->__sock.ipv6),
            &sin6->sin6_addr.in6_u.u6_addr8);
        unsigned short host_port = bpf_ntohs(port);

        if (host_port > 0 && host_port < 1024)
        {
            sock_bind_evt->__sock.is_important_port = 1;
        }
    }
    else if (family == AF_UNIX || family == AF_LOCAL)
    {
        struct sockaddr_un *sin_u = (struct sockaddr_un *)addr;
        sock_bind_evt->__sock.is_important_port = -1;
        bpf_probe_read_kernel_str(
            sock_bind_evt->__sock.path,
            sizeof(sock_bind_evt->__sock.path),
            &sin_u->sun_path);
        // prob aici
        struct sock* sk_sock = BPF_CORE_READ(sock,sk);
        struct unix_sock *unix_sock = (struct unix_sock *)sk_sock;
        struct pid *peer_pid = BPF_CORE_READ(sk_sock, sk_peer_pid);
        if (peer_pid)
        {
            unsigned int level = BPF_CORE_READ(peer_pid, level);
            pid_t pid = BPF_CORE_READ(peer_pid, numbers[level].nr);
            sock_bind_evt->__sock.peer_pid = pid;
        }
        const struct cred* peer_cred = BPF_CORE_READ(unix_sock,peer,sk_peer_cred);
        sock_bind_evt->__sock.peer_uid = BPF_CORE_READ(peer_cred,uid.val); 
        sock_bind_evt->__sock.peer_gid = BPF_CORE_READ(peer_cred,gid.val);
    }
    else if (family == AF_PACKET)
    {
        struct packet_sock *packet_sock = (struct packet_sock *)addr;
        int ifindex = BPF_CORE_READ(packet_sock, ifindex);
        sock_bind_evt->__sock.ifindex = ifindex;
    }

    sock_bind_evt->__auth.is_success = -1;
    sock_bind_evt->__auth.is_switching_user = -1;
    sock_bind_evt->__auth.is_switching_root = -1;
    sock_bind_evt->__auth.is_changing_password = -1;
    sock_bind_evt->__auth.is_root_command = -1;
    __builtin_memcpy(sock_bind_evt->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(sock_bind_evt->__auth.login_type, "void", sizeof("void"));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(sock_bind_evt->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // ─────────────────────────────
    // 📂 FILE SECTION DEFAULTS
    // ─────────────────────────────
    sock_bind_evt->mode = 0;
    sock_bind_evt->new_mode = 0;
    sock_bind_evt->old_uid = sock_bind_evt->__generics.uid;
    sock_bind_evt->new_uid = sock_bind_evt->old_uid;
    sock_bind_evt->old_gid = sock_bind_evt->__generics.gid;
    sock_bind_evt->new_gid = sock_bind_evt->old_gid;

    // sock_bind_evt->old_size = -1;
    // sock_bind_evt->new_size = -1;

    sock_bind_evt->was_permission_changed = 0;
    sock_bind_evt->was_owner_changed = 0;
    sock_bind_evt->was_group_changed = 0;
    // sock_bind_evt->was_size_extended = 0;
    sock_bind_evt->was_creation_time_changed = 0;
    sock_bind_evt->was_access_time_changed = 0; // writing updates atime
    sock_bind_evt->was_modified_time_changed = 0;

    // file timestamps (approximate)
    sock_bind_evt->old_atime = -1;
    sock_bind_evt->new_atime = -1;
    sock_bind_evt->old_mtime = -1;
    sock_bind_evt->new_mtime = -1;
    sock_bind_evt->old_ctime = -1;
    sock_bind_evt->new_ctime = -1;


    // sensitive bits / metadata
    sock_bind_evt->is_sensitive_file = -1;
    sock_bind_evt->was_suid_changed = -1;
    sock_bind_evt->was_sgid_changed = -1;
    sock_bind_evt->was_sticky_changed = -1;

    // dev + link info
    sock_bind_evt->dev_major = -1;
    sock_bind_evt->dev_minor = -1;
    sock_bind_evt->dev_major_new = -1;
    sock_bind_evt->dev_minor_new = -1;
    sock_bind_evt->rdev_major = -1;
    sock_bind_evt->rdev_minor = -1;
    // sock_bind_evt->i_bdev_major = -1;
    // sock_bind_evt->i_bdev_minor = -1;
    sock_bind_evt->rdev_major_new = -1;
    sock_bind_evt->rdev_minor_new = -1;
    // sock_bind_evt->i_bdev_major_new = -1;
    // sock_bind_evt->i_bdev_minor_new = -1;

    sock_bind_evt->is_symlink = -1;
    sock_bind_evt->was_file_created = -1;
    sock_bind_evt->was_dir_removed = -1;

    bpf_ringbuf_submit(sock_bind_evt, 0);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
    __u32 *my_pid;
    __u32 key = 0;
    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked){
        return 0;
    }
    __u8 *isCommSocketBlocked = bpf_map_lookup_elem(&socket_comm_filtering, comm);

    if (isCommSocketBlocked){
        return 0;
    }

    char isMatch = iterate(comm);
    if (isMatch == 1)
    {
        return 0;
    }



    TrackFileChanges *sock_connect_evt = bpf_ringbuf_reserve(&file_events, sizeof(*sock_connect_evt), 0);
    if (!sock_connect_evt)
    {
        bpf_printk("bpf_ringbuf_reserve failed for socket create event\n");
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    u8 kern_sock = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock);
    sock_connect_evt->__sock.kernel_sock = kern_sock;
    if (sock_connect_evt->__sock.kernel_sock == 1)
    {
        bpf_ringbuf_discard(sock_connect_evt,0);
        return 0;
    }

    __builtin_memcpy(sock_connect_evt->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->new_filename, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->file_type, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->file_type_new, "void", sizeof("void"));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);


    sock_connect_evt->__generics.evt_type = EVENT_SOCKET_CONNECT_OUTBOUND;
    sock_connect_evt->__generics.pid = pid;
    sock_connect_evt->__generics.ppid = realPPID;
    sock_connect_evt->__generics.uid = (__u32)bpf_get_current_uid_gid();
    sock_connect_evt->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    sock_connect_evt->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(sock_connect_evt->__generics.comm, sizeof(sock_connect_evt->__generics.comm), comm);
    sock_connect_evt->__sock.is_important_port = 0;
    sock_connect_evt->__sock.is_success = 0;
    if (sock_connect_evt->__generics.exit_code >= 0)
    {
        sock_connect_evt->__sock.is_success = 1;
    }
    sock_connect_evt->comm_timestamp = bpf_ktime_get_tai_ns();
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    sock_connect_evt->__generics.duration_ns = bpf_ktime_get_ns() - start_time;


    __u16 type = BPF_CORE_READ(sk, sk_type);         // The SOCK_STREAM, SOCK_DGRAM value
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol); // The IPPROTO_TCP, IPPROTO_UDP value

    sock_connect_evt->__sock.peer_pid = -1;
    sock_connect_evt->__sock.peer_uid = -1;
    sock_connect_evt->__sock.peer_gid = -1;
    sock_connect_evt->__sock.ifindex = -1;
    sock_connect_evt->__sock.kernel_sock = 0;
    sock_connect_evt->__sock.local_ipv4_socket_addr = -1;
    sock_connect_evt->__sock.local_socket_port = -1;
    __builtin_memcpy(sock_connect_evt->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->__sock.path, "void", sizeof("void"));

    // sa_family
    sa_family_t family = BPF_CORE_READ(addr, sa_family);
    sock_connect_evt->__sock.protocol_family = family;
    sock_connect_evt->__sock.socket_type = type;
    sock_connect_evt->__sock.protocol = protocol;

    if (family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        unsigned short port = BPF_CORE_READ(sin, sin_port);
        // unsigned int ip = bpf_ntohl(BPF_CORE_READ(sin, sin_addr.s_addr));
        unsigned int ip = BPF_CORE_READ(sin, sin_addr.s_addr);


        // converting from network byte order to host byte order
        unsigned short host_port = bpf_ntohs(port);

        if (host_port > 0 && host_port < 1024)
        {
            sock_connect_evt->__sock.is_important_port = 1;
        }

        sock_connect_evt->__sock.port = host_port;
        sock_connect_evt->__sock.ipv4 = ip;
    }
    else if (family == AF_INET6)
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        unsigned short port = BPF_CORE_READ(sin6, sin6_port);
        bpf_probe_read_kernel(
            sock_connect_evt->__sock.ipv6,
            sizeof(sock_connect_evt->__sock.ipv6),
            &sin6->sin6_addr.in6_u.u6_addr8);
        unsigned short host_port = bpf_ntohs(port);

        if (host_port > 0 && host_port < 1024)
        {
            sock_connect_evt->__sock.is_important_port = 1;
        }
    }
    else if (family == AF_UNIX || family == AF_LOCAL)
    {
        struct sockaddr_un *sin_u = (struct sockaddr_un *)addr;
        sock_connect_evt->__sock.is_important_port = -1;
        bpf_probe_read_kernel_str(
            sock_connect_evt->__sock.path,
            sizeof(sock_connect_evt->__sock.path),
            &sin_u->sun_path);
        
        struct sock* sk = BPF_CORE_READ(sock,sk);
        struct unix_sock *unix_sock = (struct unix_sock* )sk;
        struct pid *peer_pid = BPF_CORE_READ(sk, sk_peer_pid);
        if (peer_pid)
        {
            unsigned int level = BPF_CORE_READ(peer_pid, level);
            pid_t pid = BPF_CORE_READ(peer_pid, numbers[level].nr);
            sock_connect_evt->__sock.peer_pid = pid;
        }
        const struct cred* peer_cred = BPF_CORE_READ(unix_sock,peer,sk_peer_cred);
        sock_connect_evt->__sock.peer_uid = BPF_CORE_READ(peer_cred,uid.val); 
        sock_connect_evt->__sock.peer_gid = BPF_CORE_READ(peer_cred,gid.val);
    }
    else if (family == AF_PACKET)
    {
        struct packet_sock *packet_sock = (struct packet_sock *)addr;
        int ifindex = BPF_CORE_READ(packet_sock, ifindex);
        sock_connect_evt->__sock.ifindex = ifindex;
    }

    sock_connect_evt->__auth.is_success = -1;
    sock_connect_evt->__auth.is_switching_user = -1;
    sock_connect_evt->__auth.is_switching_root = -1;
    sock_connect_evt->__auth.is_changing_password = -1;
    sock_connect_evt->__auth.is_root_command = -1;
    __builtin_memcpy(sock_connect_evt->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(sock_connect_evt->__auth.login_type, "void", sizeof("void"));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(sock_connect_evt->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // ─────────────────────────────
    // 📂 FILE SECTION DEFAULTS
    // ─────────────────────────────
    sock_connect_evt->mode = 0;
    sock_connect_evt->new_mode = 0;
    sock_connect_evt->old_uid = sock_connect_evt->__generics.uid;
    sock_connect_evt->new_uid = sock_connect_evt->old_uid;
    sock_connect_evt->old_gid = sock_connect_evt->__generics.gid;
    sock_connect_evt->new_gid = sock_connect_evt->old_gid;

    // sock_connect_evt->old_size = -1;
    // sock_connect_evt->new_size = -1;

    sock_connect_evt->was_permission_changed = 0;
    sock_connect_evt->was_owner_changed = 0;
    sock_connect_evt->was_group_changed = 0;
    // sock_connect_evt->was_size_extended = 0;
    sock_connect_evt->was_creation_time_changed = 0;
    sock_connect_evt->was_access_time_changed = 0; // writing updates atime
    sock_connect_evt->was_modified_time_changed = 0;

    // file timestamps (approximate)
    sock_connect_evt->old_atime = -1;
    sock_connect_evt->new_atime = -1;
    sock_connect_evt->old_mtime = -1;
    sock_connect_evt->new_mtime = -1;
    sock_connect_evt->old_ctime = -1;
    sock_connect_evt->new_ctime = -1;


    // sensitive bits / metadata
    sock_connect_evt->is_sensitive_file = -1;
    sock_connect_evt->was_suid_changed = -1;
    sock_connect_evt->was_sgid_changed = -1;
    sock_connect_evt->was_sticky_changed = -1;

    // dev + link info
    sock_connect_evt->dev_major = -1;
    sock_connect_evt->dev_minor = -1;
    sock_connect_evt->dev_major_new = -1;
    sock_connect_evt->dev_minor_new = -1;
    sock_connect_evt->rdev_major = -1;
    sock_connect_evt->rdev_minor = -1;
    // sock_connect_evt->i_bdev_major = -1;
    // sock_connect_evt->i_bdev_minor = -1;
    sock_connect_evt->rdev_major_new = -1;
    sock_connect_evt->rdev_minor_new = -1;
    // sock_connect_evt->i_bdev_major_new = -1;
    // sock_connect_evt->i_bdev_minor_new = -1;

    sock_connect_evt->is_symlink = -1;
    sock_connect_evt->was_file_created = -1;
    sock_connect_evt->was_dir_removed = -1;

    bpf_ringbuf_submit(sock_connect_evt, 0);
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog)
{
    __u32 *my_pid;
    __u32 key = 0;
    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ppid = (__u32)pid_tgid;

    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked){
        return 0;
    }
    __u8 *isCommSocketBlocked = bpf_map_lookup_elem(&socket_comm_filtering, comm);

    if (isCommSocketBlocked){
        return 0;
    }


    char isMatch = iterate(comm);
    if (isMatch == 1)
    {
        return 0;
    }


    

    TrackFileChanges *sock_listen_event = bpf_ringbuf_reserve(&file_events, sizeof(*sock_listen_event), 0);
    if (!sock_listen_event)
    {
        bpf_printk("bpf_ringbuf_reserve failed for socket create event\n");
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    u8 kern_sock = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock);
    sock_listen_event->__sock.kernel_sock = kern_sock;
    
    if (sock_listen_event->__sock.kernel_sock == 1)
    {
        bpf_ringbuf_discard(sock_listen_event,0);
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    __builtin_memcpy(sock_listen_event->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->new_filename, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->file_type, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->file_type_new, "void", sizeof("void"));

    sock_listen_event->__generics.evt_type = EVENT_SOCKET_LISTEN;
    sock_listen_event->__generics.pid = pid;
    sock_listen_event->__generics.ppid = realPPID;
    sock_listen_event->__generics.uid = (__u32)bpf_get_current_uid_gid();
    sock_listen_event->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    sock_listen_event->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(sock_listen_event->__generics.comm, sizeof(sock_listen_event->__generics.comm), comm);
    sock_listen_event->__sock.is_important_port = 0;
    sock_listen_event->__sock.is_success = 0;
    if (sock_listen_event->__generics.exit_code >= 0)
    {
        sock_listen_event->__sock.is_success = 1;
    }
    sock_listen_event->__sock.backlog_value = backlog;
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    sock_listen_event->__generics.duration_ns = bpf_ktime_get_ns() - start_time;
    sock_listen_event->comm_timestamp = bpf_ktime_get_tai_ns();


    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 type = BPF_CORE_READ(sk, sk_type);         // The SOCK_STREAM, SOCK_DGRAM value
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol); // The IPPROTO_TCP, IPPROTO_UDP value

    sock_listen_event->__sock.protocol_family = family;
    sock_listen_event->__sock.socket_type = type;
    sock_listen_event->__sock.protocol = protocol;

    sock_listen_event->__sock.peer_pid = -1;
    sock_listen_event->__sock.peer_uid = -1;
    sock_listen_event->__sock.peer_gid = -1;
    sock_listen_event->__sock.ifindex = -1;
    sock_listen_event->__sock.kernel_sock = 0;
    sock_listen_event->__sock.local_ipv4_socket_addr = -1;
    sock_listen_event->__sock.local_socket_port = -1;
    __builtin_memcpy(sock_listen_event->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->__sock.path, "void", sizeof("void"));

    if (family == AF_INET)
    {
        // local connection
        // unsigned int ip_local = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        unsigned int ip_local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        unsigned short port_local = BPF_CORE_READ(sk, __sk_common.skc_num);

        // outbound connection
        // unsigned int ip_out = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
        unsigned int ip_out = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        unsigned short port_out = BPF_CORE_READ(sk, __sk_common.skc_dport);

        // converting from network byte order to host byte order
        unsigned short host_port_local = bpf_ntohs(port_local);
        unsigned short host_port_out = bpf_ntohs(port_out);

        if (host_port_local > 0 && host_port_local < 1024)
        {
            sock_listen_event->__sock.is_important_port = 1;
        }

        sock_listen_event->__sock.port = host_port_out;
        sock_listen_event->__sock.ipv4 = ip_out;

        sock_listen_event->__sock.local_socket_port = host_port_local;
        sock_listen_event->__sock.local_ipv4_socket_addr = ip_local;
    }
    else if (family == AF_INET6)
    {
        // struct in6_addr skc_v6_daddr;
        // struct in6_addr skc_v6_rcv_saddr;

        unsigned short port_local = BPF_CORE_READ(sk, __sk_common.skc_num);
        unsigned short port_out = BPF_CORE_READ(sk, __sk_common.skc_dport);

        bpf_probe_read_kernel(
            sock_listen_event->__sock.ipv6,
            sizeof(sock_listen_event->__sock.ipv6),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_probe_read_kernel(
            sock_listen_event->__sock.local_ipv6_socket_addr,
            sizeof(sock_listen_event->__sock.local_ipv6_socket_addr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        unsigned short host_port_local = bpf_ntohs(port_local);
        unsigned short host_port_out = bpf_ntohs(port_out);

        if (host_port_local > 0 && host_port_local < 1024)
        {
            sock_listen_event->__sock.is_important_port = 1;
        }
    }
    sock_listen_event->__auth.is_success = -1;
    sock_listen_event->__auth.is_switching_user = -1;
    sock_listen_event->__auth.is_switching_root = -1;
    sock_listen_event->__auth.is_changing_password = -1;
    sock_listen_event->__auth.is_root_command = -1;
    __builtin_memcpy(sock_listen_event->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(sock_listen_event->__auth.login_type, "void", sizeof("void"));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(sock_listen_event->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // ─────────────────────────────
    // 📂 FILE SECTION DEFAULTS
    // ─────────────────────────────
    sock_listen_event->mode = 0;
    sock_listen_event->new_mode = 0;
    sock_listen_event->old_uid = sock_listen_event->__generics.uid;
    sock_listen_event->new_uid = sock_listen_event->old_uid;
    sock_listen_event->old_gid = sock_listen_event->__generics.gid;
    sock_listen_event->new_gid = sock_listen_event->old_gid;

    // sock_listen_event->old_size = -1;
    // sock_listen_event->new_size = -1;

    sock_listen_event->was_permission_changed = 0;
    sock_listen_event->was_owner_changed = 0;
    sock_listen_event->was_group_changed = 0;
    // sock_listen_event->was_size_extended = 0;
    sock_listen_event->was_creation_time_changed = 0;
    sock_listen_event->was_access_time_changed = 0; // writing updates atime
    sock_listen_event->was_modified_time_changed = 0;

    // file timestamps (approximate)
    sock_listen_event->old_atime = -1;
    sock_listen_event->new_atime = -1;
    sock_listen_event->old_mtime = -1;
    sock_listen_event->new_mtime = -1;
    sock_listen_event->old_ctime = -1;
    sock_listen_event->new_ctime = -1;

    // sensitive bits / metadata
    sock_listen_event->is_sensitive_file = -1;
    sock_listen_event->was_suid_changed = -1;
    sock_listen_event->was_sgid_changed = -1;
    sock_listen_event->was_sticky_changed = -1;

    // dev + link info
    sock_listen_event->dev_major = -1;
    sock_listen_event->dev_minor = -1;
    sock_listen_event->dev_major_new = -1;
    sock_listen_event->dev_minor_new = -1;
    sock_listen_event->rdev_major = -1;
    sock_listen_event->rdev_minor = -1;
    // sock_listen_event->i_bdev_major = -1;
    // sock_listen_event->i_bdev_minor = -1;
    sock_listen_event->rdev_major_new = -1;
    sock_listen_event->rdev_minor_new = -1;
    // sock_listen_event->i_bdev_major_new = -1;
    // sock_listen_event->i_bdev_minor_new = -1;

    sock_listen_event->is_symlink = -1;
    sock_listen_event->was_file_created = -1;
    sock_listen_event->was_dir_removed = -1;

    bpf_ringbuf_submit(sock_listen_event, 0);
    return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *listening_socket, struct socket *connection_socket)
{
    __u32 *my_pid;
    __u32 key = 0;
    my_pid = bpf_map_lookup_elem(&self_pid, &key);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 ppid = (__u32)pid_tgid;

    if (my_pid){
        if (*my_pid == pid || *my_pid == ppid){
            return 0;
        }
    }

    char comm[TYPE];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u8 *isCommBlocked = bpf_map_lookup_elem(&comm_filtering, comm);
    if (isCommBlocked){
        return 0;
    }
    __u8 *isCommSocketBlocked = bpf_map_lookup_elem(&socket_comm_filtering, comm);
    if (isCommSocketBlocked){
        return 0;
    }

    char isMatch = iterate(comm);
    if (isMatch == 1)
    {
        return 0;
    }




    TrackFileChanges *sock_accept_evt = bpf_ringbuf_reserve(&file_events, sizeof(*sock_accept_evt), 0);
    if (!sock_accept_evt)
    {
        bpf_printk("bpf_ringbuf_reserve failed for socket create event\n");
        return 0;
    }
    struct sock *sk = BPF_CORE_READ(listening_socket, sk);
    u8 kern_sock = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock);
    sock_accept_evt->__sock.kernel_sock = kern_sock;

    if (sock_accept_evt->__sock.kernel_sock == 1)
    {
        bpf_ringbuf_discard(sock_accept_evt,0);
        return 0;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 realPPID = BPF_CORE_READ(task, real_parent, tgid);

    __builtin_memcpy(sock_accept_evt->__generics.filename, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->new_filename, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->file_type, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->file_type_new, "void", sizeof("void"));

    sock_accept_evt->__generics.evt_type = EVENT_SOCKET_ACCEPT;
    sock_accept_evt->__generics.pid = pid;
    sock_accept_evt->__generics.ppid = realPPID;
    sock_accept_evt->__generics.uid = (__u32)bpf_get_current_uid_gid();
    sock_accept_evt->__generics.gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    sock_accept_evt->__generics.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_probe_read_kernel_str(sock_accept_evt->__generics.comm, sizeof(sock_accept_evt->__generics.comm), comm);
    sock_accept_evt->__sock.is_important_port = 0;
    sock_accept_evt->__sock.is_success = 0;
    if (sock_accept_evt->__generics.exit_code >= 0)
    {
        sock_accept_evt->__sock.is_success = 1;
    }
    u64 start_time = 0;
    start_time = BPF_CORE_READ(task, start_time);
    sock_accept_evt->__generics.duration_ns = bpf_ktime_get_ns() - start_time;
    sock_accept_evt->comm_timestamp = bpf_ktime_get_tai_ns();


    struct sock *connection_sock = BPF_CORE_READ(connection_socket, sk);

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 type = BPF_CORE_READ(sk, sk_type);         // The SOCK_STREAM, SOCK_DGRAM value
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol); // The IPPROTO_TCP, IPPROTO_UDP value

    sock_accept_evt->__sock.protocol_family = family;
    sock_accept_evt->__sock.socket_type = type;
    sock_accept_evt->__sock.protocol = protocol;

    sock_accept_evt->__sock.peer_pid = -1;
    sock_accept_evt->__sock.peer_uid = -1;
    sock_accept_evt->__sock.peer_gid = -1;
    sock_accept_evt->__sock.ifindex = -1;
    sock_accept_evt->__sock.kernel_sock = 0;
    sock_accept_evt->__sock.local_ipv4_socket_addr = -1;
    sock_accept_evt->__sock.local_socket_port = -1;
    __builtin_memcpy(sock_accept_evt->__sock.path, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->__sock.local_ipv6_socket_addr, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->__sock.path, "void", sizeof("void"));

    if (family == AF_INET)
    {
        // local connection
        // unsigned int ip_local = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        unsigned int ip_local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        unsigned short port_local = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_num));

        // outbound connection
        // unsigned int ip_out = BPF_CORE_READ(connection_sock, __sk_common.skc_daddr);
        unsigned int ip_out = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        unsigned short port_out = BPF_CORE_READ(connection_sock, __sk_common.skc_dport);

        // converting from network byte order to host byte order
        unsigned short host_port_local = bpf_ntohs(port_local);
        unsigned short host_port_out = bpf_ntohs(port_out);

        if (host_port_local > 0 && host_port_local < 1024)
        {
            sock_accept_evt->__sock.is_important_port = 1;
        }

        sock_accept_evt->__sock.port = host_port_out;
        sock_accept_evt->__sock.ipv4 = ip_out;

        sock_accept_evt->__sock.local_socket_port = host_port_local;
        sock_accept_evt->__sock.local_ipv4_socket_addr = ip_local;
    }
    else if (family == AF_INET6)
    {
        // struct in6_addr skc_v6_daddr;
        // struct in6_addr skc_v6_rcv_saddr;

        unsigned short port_local = BPF_CORE_READ(sk, __sk_common.skc_num);
        unsigned short port_out = BPF_CORE_READ(connection_sock, __sk_common.skc_dport);

        bpf_probe_read_kernel(
            sock_accept_evt->__sock.ipv6,
            sizeof(sock_accept_evt->__sock.ipv6),
            &connection_sock->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_probe_read_kernel(
            sock_accept_evt->__sock.local_ipv6_socket_addr,
            sizeof(sock_accept_evt->__sock.local_ipv6_socket_addr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        unsigned short host_port_local = bpf_ntohs(port_local);
        unsigned short host_port_out = bpf_ntohs(port_out);

        if (host_port_local > 0 && host_port_local < 1024)
        {
            sock_accept_evt->__sock.is_important_port = 1;
        }
    }
    else if (family == AF_UNIX || family == AF_LOCAL)
    {
        
        sock_accept_evt->__sock.is_important_port = -1;
        struct unix_sock *unix_sock = (struct unix_sock*)sk;
        struct unix_address *addr = BPF_CORE_READ(unix_sock, addr);
        bpf_probe_read_kernel_str(
            sock_accept_evt->__sock.path,
            sizeof(sock_accept_evt->__sock.path),
            &addr->name[0].sun_path);
        struct pid *peer_pid = BPF_CORE_READ(sk,sk_peer_pid);
        if (peer_pid)
        {
            unsigned int level = BPF_CORE_READ(peer_pid, level);
            pid_t pid = BPF_CORE_READ(peer_pid, numbers[level].nr);
            sock_accept_evt->__sock.peer_pid = pid;
        }
        const struct cred* peer_cred = BPF_CORE_READ(unix_sock,peer,sk_peer_cred);
        sock_accept_evt->__sock.peer_uid = BPF_CORE_READ(peer_cred,uid.val); 
        sock_accept_evt->__sock.peer_gid = BPF_CORE_READ(peer_cred,gid.val);
    }

    sock_accept_evt->__auth.is_success = -1;
    sock_accept_evt->__auth.is_switching_user = -1;
    sock_accept_evt->__auth.is_switching_root = -1;
    sock_accept_evt->__auth.is_changing_password = -1;
    sock_accept_evt->__auth.is_root_command = -1;
    __builtin_memcpy(sock_accept_evt->__auth.name, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->__auth.rhost, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->__auth.rname, "void", sizeof("void"));
    __builtin_memcpy(sock_accept_evt->__auth.login_type, "void", sizeof("void"));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
    {
        __builtin_memset(sock_accept_evt->__generics.argv[i], 0, MAX_ARGV_LEN);
    }

    // ─────────────────────────────
    // 📂 FILE SECTION DEFAULTS
    // ─────────────────────────────
    sock_accept_evt->mode = 0;
    sock_accept_evt->new_mode = 0;
    sock_accept_evt->old_uid = sock_accept_evt->__generics.uid;
    sock_accept_evt->new_uid = sock_accept_evt->old_uid;
    sock_accept_evt->old_gid = sock_accept_evt->__generics.gid;
    sock_accept_evt->new_gid = sock_accept_evt->old_gid;

    // sock_accept_evt->old_size = -1;
    // sock_accept_evt->new_size = -1;

    sock_accept_evt->was_permission_changed = 0;
    sock_accept_evt->was_owner_changed = 0;
    sock_accept_evt->was_group_changed = 0;
    // sock_accept_evt->was_size_extended = 0;
    sock_accept_evt->was_creation_time_changed = 0;
    sock_accept_evt->was_access_time_changed = 0; // writing updates atime
    sock_accept_evt->was_modified_time_changed = 0;

    // file timestamps (approximate)
    sock_accept_evt->old_atime = -1;
    sock_accept_evt->new_atime = -1;
    sock_accept_evt->old_mtime = -1;
    sock_accept_evt->new_mtime = -1;
    sock_accept_evt->old_ctime = -1;
    sock_accept_evt->new_ctime = -1;

    // sensitive bits / metadata
    sock_accept_evt->is_sensitive_file = -1;
    sock_accept_evt->was_suid_changed = -1;
    sock_accept_evt->was_sgid_changed = -1;
    sock_accept_evt->was_sticky_changed = -1;

    // dev + link info
    sock_accept_evt->dev_major = -1;
    sock_accept_evt->dev_minor = -1;
    sock_accept_evt->dev_major_new = -1;
    sock_accept_evt->dev_minor_new = -1;
    sock_accept_evt->rdev_major = -1;
    sock_accept_evt->rdev_minor = -1;
    // sock_accept_evt->i_bdev_major = -1;
    // sock_accept_evt->i_bdev_minor = -1;
    sock_accept_evt->rdev_major_new = -1;
    sock_accept_evt->rdev_minor_new = -1;
    // sock_accept_evt->i_bdev_major_new = -1;
    // sock_accept_evt->i_bdev_minor_new = -1;

    sock_accept_evt->is_symlink = -1;
    sock_accept_evt->was_file_created = -1;
    sock_accept_evt->was_dir_removed = -1;

    bpf_ringbuf_submit(sock_accept_evt, 0);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
