#ifndef __UTILS__
#define __UTILS__
#define FILE_NAME_LEN 4096
#define EXE_BUFFER 512
#define MAX_ARGV_LEN 64
#define MAX_ARGS_CAPTURED 12
#define TYPE 16
#define TYPE_3 48
#define MAX_PATTERN_LEN TYPE
#define MAX_CHAR_LEN 256
#define MAX_MAP_ELEMS 1024
#define LITTLE_MAP_SIZE 32
#define MAX_ITERS_FOR_STRSTR 128
#define MAX_RESOLVE_PATH FILENAME_MAX
// O_* FLAGS
// #define O_RDONLY        00000000
// #define O_WRONLY        00000001
// #define O_RDWR          00000002
// #define O_ACCMODE       00000003
// #define O_CREAT         00000100    /* Create file if it does not exist */
// #define O_EXCL          00000200    /* Error if O_CREAT and file exists */
// #define O_NOCTTY        00000400    /* Do not assign controlling terminal */
// #define O_TRUNC         00001000    /* Truncate file to 0 size if it exists */
// #define O_APPEND        00002000    /* Append mode */
// #define O_NONBLOCK      00004000    /* Non-blocking mode */
// #define O_DSYNC         00010000    /* Wait for data integrity */
// #define FASYNC          00020000    /* fcntl-style asynchronous I/O */
// #define O_DIRECT        00040000    /* Direct I/O (minimize cache effects) */
// #define O_LARGEFILE     00100000    /* Allow large files (>2GB on 32-bit) */
// #define O_DIRECTORY     00200000    /* Must be a directory */
// #define O_NOFOLLOW      00400000    /* Do not follow symlinks */
#define O_NOATIME       01000000    /* Do not update access time */
// #define O_CLOEXEC       02000000    /* Close on exec() */
// #define O_PATH          04000000    /* Obtain a file descriptor without I/O */
// #define O_TMPFILE       020000000   /* Create unnamed temporary file */
// #define O_SYNC          04000000    /* Write operations complete as sync I/O */
// #define O_NDELAY        O_NONBLOCK  /* Compatibility alias */
#define _S_IFMT   0170000  // bit mask for the file type bit fields
#define _S_IFREG  0100000  // regular file
#define _S_IFDIR  0040000  // directory
#define _S_IFCHR  0020000  // character device
#define _S_IFBLK  0060000  // block device
#define _S_IFIFO  0010000  // FIFO/pipe
#define _S_IFLNK  0120000  // symbolic link
#define _S_IFSOCK 0140000  // socket
#define _S_ISUID 04000
#define _S_ISGID 02000
#define _S_ISVTX 01000
#define _S_IWOTH 00002
#define SUID _S_ISUID
#define SGID _S_ISGID
// #define MAY_EXEC		0x00000001
// #define MAY_WRITE		0x00000002
// #define MAY_READ		0x00000004
// #define MAY_APPEND		0x00000008
// #define MAY_ACCESS		0x00000010
// #define MAY_OPEN		0x00000020
// #define MAY_CHDIR		0x00000040
#define ATTR_MODE	1
#define ATTR_UID	2
#define ATTR_GID	4
// #define ATTR_SIZE	8
#define ATTR_ATIME	16
#define ATTR_MTIME	32
#define ATTR_CTIME	64
// #define ATTR_ATIME_SET	128
// #define ATTR_MTIME_SET	256
// familty types
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/
// #define AF_NETLINK	16
// #define AF_ROUTE	AF_NETLINK
#define AF_PACKET	17	/* Packet family		*/
// Socket types
// #define SOCK_STREAM	1,
// #define SOCK_DGRAM	2,
// #define SOCK_RAW	3,
// #define SOCK_RDM	4,
// #define SOCK_SEQPACKET	5,
// #define SOCK_DCCP	6,
// #define SOCK_PACKET	10,
// Protocol
// #define IPPROTO_IP 0
// #define IPPROTO_ICMP 1
// #define IPPROTO_TCP 6
// #define IPPROTO_UDP 17
// #define IPPROTO_SCTP 132 // Sream control transport protocol

// Permission bits mask
#define MODE_MASK 07777

// Context struct for bpf_loop
struct iterate_ctx {
    const char* filename;
    char match_found;
};


typedef enum {
    EVENT_FILE_OPEN_AND_WRITE = 1, 
    EVENT_FILE_OPEN_AND_READ,
    EVENT_EXECVE,
    EVENT_PROCESS_EXIT,
    EVENT_INODE_SETATTR,
    EVENT_INODE_CREATE,
    EVENT_INODE_LINK,
    EVENT_INODE_SYMLINK,
    EVENT_INODE_MKDIR,
    EVENT_INODE_RMDIR,
    EVENT_INODE_MKNOD,
    EVENT_INODE_RENAME,
    EVENT_AUTH,
    EVENT_PASSWD_CHANGE,
    EVENT_CHANGE_USER,
    EVENT_SOCKET_CREATION,
    EVENT_SOCKET_BIND,
    EVENT_SOCKET_CONNECT_OUTBOUND,
    EVENT_SOCKET_LISTEN,
    EVENT_SOCKET_ACCEPT,
}event_type;

typedef struct {
    unsigned long long duration_ns;  // 8 bytes
    event_type evt_type;             // 4 bytes
    unsigned int uid;                // 4 bytes
    unsigned int gid;                // 4 bytes
    unsigned int pid;                // 4 bytes
    unsigned int ppid;               // 4 bytes
    int exit_code;                   // 4 bytes
    char argv[MAX_ARGS_CAPTURED][MAX_ARGV_LEN]; // 8x64 bytes
    char filename[MAX_CHAR_LEN];    // 256 bytes
    char comm[MAX_ARGV_LEN];         // 64 bytes
} Generics;


typedef struct {
    unsigned char is_success; // 1
    unsigned char is_switching_user; // 1
    unsigned char is_switching_root; // 1 
    unsigned char is_changing_password; // 1 
    unsigned char is_root_command; // 1
    unsigned char padding[3]; 
    char name[MAX_ARGV_LEN];
    char rhost[MAX_ARGV_LEN];
    char rname[MAX_ARGV_LEN];
    char login_type[TYPE];
} AuthEvent;

typedef struct {
    int protocol_family;       // 4
    int socket_type;           // 4
    int protocol;              // 4
    int peer_pid;              // 4
    int peer_uid;              // 4
    int peer_gid;              // 4
    int backlog_value;         // 4
    int ifindex;               // 4
    unsigned int ipv4;         // 4
    unsigned int local_ipv4_socket_addr; // 4
    unsigned short port;       // 2
    unsigned char is_important_port; // 1
    unsigned char kernel_sock; // 1
    unsigned char is_success;  // 1
    unsigned short local_socket_port;  // 2
    unsigned char padding2;
    unsigned char ipv6[TYPE];    // 16
    unsigned char local_ipv6_socket_addr[TYPE]; // 16
    char path[108];            // 108
} SocketEvent;


typedef struct {
    Generics __generics;
    AuthEvent __auth;
    SocketEvent __sock;

    unsigned long long old_mtime; // 8
    unsigned long long new_mtime; // 8
    unsigned long long old_ctime; // 8
    unsigned long long new_ctime; // 8
    unsigned long long old_atime; // 8
    unsigned long long new_atime; // 8
    unsigned long long comm_timestamp; // 8
    unsigned long fptr;
    int has_emitted_read;       
    int has_emitted_write;  

    unsigned long inode_number; // 8
    unsigned long inode_number_new; // 8

    unsigned int mode; // 4
    unsigned int new_mode; // 4
    unsigned int old_uid; // 4
    unsigned int new_uid; // 4
    unsigned int old_gid; // 4
    unsigned int new_gid; // 4
    // Device numbers
    unsigned int dev_major; // 4
    unsigned int dev_minor; // 4
    unsigned int dev_major_new; // 4
    unsigned int dev_minor_new; // 4
    unsigned int rdev_major; // 4
    unsigned int rdev_minor; // 4
    unsigned int rdev_major_new; // 4
    unsigned int rdev_minor_new; // 4


    // Sensitive / flags
    unsigned char was_success; // 1
    unsigned char do_not_update_atime; // 1
    unsigned char was_file_created; // 1
    unsigned char was_file_modified;  // 1  
    unsigned char is_sensitive_file; // 1
    unsigned char is_symlink; // 1
    unsigned char was_suid_changed; // 1
    unsigned char suid_set; // 1
    unsigned char suid_cleared; // 1
    unsigned char was_sgid_changed; // 1
    unsigned char sgid_set; // 1
    unsigned char sgid_cleared; // 1
    unsigned char was_sticky_changed; // 1
    unsigned char sticky_set; // 1
    unsigned char sticky_cleared; // 1
    unsigned char was_permission_changed; // 1
    unsigned char was_owner_changed; // 1
    unsigned char was_group_changed; // 1
    unsigned char was_creation_time_changed; // 1
    unsigned char was_access_time_changed; // 1
    unsigned char was_modified_time_changed; // 1
    unsigned char is_target_dir_world_writable; // 1
    unsigned char is_linked_file_SGID_or_SUID; // 1
    unsigned char is_linked_to_sensitive_file; // 1
    unsigned char is_cross_user_link; // 1
    unsigned char was_dir_removed; // 1
    unsigned char is_current_dir_world_writable; // 1
    unsigned char padding3; // 1 

    char file_type[TYPE];
    char file_type_new[TYPE];
    char new_filename[MAX_CHAR_LEN];

}TrackFileChanges;


 #endif