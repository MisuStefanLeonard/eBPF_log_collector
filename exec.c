#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include "redis/redislogic.h"
// #include "redis/redislogic.c"
#include "execve_called/exec.h"
#include "file_events/file_exec.h"
#include "execve_called/exec.skel.h"
#include "file_events/file_open.skel.h"
#include "process_events/process_exec.h"
#include "process_events/process_exec.skel.h"
#include "socket/socket.h"
#include "socket/socket_ebpf.skel.h"
#include "auth_calls/auth.h"
#include "auth_calls/auth_ebpf.skel.h"

#define MAX_SENSITIVE 256
#define MAX_PATH_LEN 256

/* Global CSV file handle */
FILE *csv_file = NULL;
static char sensitive_list[MAX_SENSITIVE][MAX_PATH_LEN];
static int sensitive_count = 0;
static int blocked_comm_count = 0;
static int blocked_filenames_count = 0;
static int blocked_patterns_count = 0;
static int blocked_socket_command_count = 0;
static int blocked_comms_from_filenames_count = 0;
static redisContext* client;
const int redisPort = 6379;
static __u8 blocked = 1;

void convert_from_int_to_ipv4(unsigned char* buff, unsigned int ipv4);
const char *event_type_to_str(event_type type);

char* createJson(TrackFileChanges event, const char *username, const char *groupname
    ,unsigned int permission_bits_octal_old_mode, unsigned int permission_bits_octal_new_mode,
    char exe[EXE_BUFFER]) {
    // 1. Where we will store the string
    char *string = NULL;
    // 2. Create the json object
    cJSON *eventJson = cJSON_CreateObject();
    if (eventJson == NULL){
        goto end;
    }
    const char* event_type_str = event_type_to_str(event.__generics.evt_type);
    /* Generics event */
    char duration_ns_buffer[64] = {};
    snprintf(duration_ns_buffer, sizeof(duration_ns_buffer), "%llu", event.__generics.duration_ns);
    cJSON_AddStringToObject(eventJson, "durations_ns", duration_ns_buffer);
    cJSON_AddNumberToObject(eventJson, "event_type", event.__generics.evt_type);
    cJSON_AddStringToObject(eventJson, "event_type_str",event_type_str);
    cJSON_AddNumberToObject(eventJson, "uid", event.__generics.uid);
    cJSON_AddStringToObject(eventJson, "username", username);
    cJSON_AddNumberToObject(eventJson, "gid", event.__generics.gid);
    cJSON_AddStringToObject(eventJson, "groupname", groupname);
    cJSON_AddNumberToObject(eventJson, "pid", event.__generics.pid);
    cJSON_AddNumberToObject(eventJson, "ppid", event.__generics.ppid);
    cJSON_AddNumberToObject(eventJson, "exit_code", event.__generics.exit_code);
    cJSON *argv_array = cJSON_CreateArray();
    if (argv_array == NULL){
        goto end;
    }
    for (int i = 0; i < MAX_ARGS_CAPTURED; i++){
        cJSON *argv_elem = cJSON_CreateString((const char*) event.__generics.argv[i]);
        if (argv_elem == NULL){
            goto end;
        }
        cJSON_AddItemToArray(argv_array, argv_elem);
    }

    cJSON_AddItemToObject(eventJson, "argv" , argv_array);

    cJSON_AddStringToObject(eventJson, "filename", event.__generics.filename);
    cJSON_AddStringToObject(eventJson, "comm", event.__generics.comm);
    cJSON_AddStringToObject(eventJson, "exe", exe);
    

    /*Auth event*/
    cJSON_AddNumberToObject(eventJson, "is_auth_success", event.__auth.is_success);
    cJSON_AddNumberToObject(eventJson, "is_switching_user", event.__auth.is_switching_user);
    cJSON_AddNumberToObject(eventJson, "is_switching_root", event.__auth.is_switching_root);
    cJSON_AddNumberToObject(eventJson, "is_changing_password", event.__auth.is_changing_password);
    cJSON_AddNumberToObject(eventJson, "is_root_command", event.__auth.is_root_command);
    cJSON_AddStringToObject(eventJson, "name", event.__auth.name);
    cJSON_AddStringToObject(eventJson, "rhost", event.__auth.rhost);
    cJSON_AddStringToObject(eventJson, "rname", event.__auth.rname);
    cJSON_AddStringToObject(eventJson, "login_type", event.__auth.login_type);

    /*Socket event*/
    cJSON_AddNumberToObject(eventJson, "protocol_family", event.__sock.protocol_family);
    cJSON_AddNumberToObject(eventJson, "socket_type", event.__sock.socket_type);
    cJSON_AddNumberToObject(eventJson, "protocol", event.__sock.protocol);
    cJSON_AddNumberToObject(eventJson, "peer_pid", event.__sock.peer_pid);
    cJSON_AddNumberToObject(eventJson, "peer_uid", event.__sock.peer_uid);
    cJSON_AddNumberToObject(eventJson, "peer_gid", event.__sock.peer_gid);
    cJSON_AddNumberToObject(eventJson, "backlog", event.__sock.backlog_value);
    cJSON_AddNumberToObject(eventJson, "ifindex", event.__sock.ifindex);

    unsigned char buff[4];
    unsigned char buff_local[4];
    // 255.255.255.255 + \0
    convert_from_int_to_ipv4(buff,event.__sock.ipv4);
    convert_from_int_to_ipv4(buff_local,event.__sock.local_ipv4_socket_addr);
    char ipv4_string[16];
    char ipv4_string_local[16];
    snprintf(ipv4_string, sizeof(ipv4_string), "%d.%d.%d.%d", buff[0],buff[1],buff[2],buff[3]);
    snprintf(ipv4_string_local, sizeof(ipv4_string_local), "%d.%d.%d.%d", buff_local[0],buff_local[1],buff_local[2],buff_local[3]);
    cJSON_AddStringToObject(eventJson, "ipv4", ipv4_string);
    cJSON_AddStringToObject(eventJson, "local_ipv4_socket_addr", ipv4_string_local);
    cJSON_AddNumberToObject(eventJson, "port", event.__sock.port);
    cJSON_AddNumberToObject(eventJson, "is_important_port", event.__sock.is_important_port);
    cJSON_AddNumberToObject(eventJson, "kernel_sock", event.__sock.kernel_sock);
    cJSON_AddNumberToObject(eventJson, "is_sock_success", event.__sock.is_success);
    cJSON_AddNumberToObject(eventJson, "local_socket_port", event.__sock.local_socket_port);

    char ipv6_str[40] = {0};
    char local_ipv6_str[40] = {0};

    snprintf(ipv6_str, sizeof(ipv6_str),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             event.__sock.ipv6[0], event.__sock.ipv6[1], event.__sock.ipv6[2], event.__sock.ipv6[3],
             event.__sock.ipv6[4], event.__sock.ipv6[5], event.__sock.ipv6[6], event.__sock.ipv6[7],
             event.__sock.ipv6[8], event.__sock.ipv6[9], event.__sock.ipv6[10], event.__sock.ipv6[11],
             event.__sock.ipv6[12], event.__sock.ipv6[13], event.__sock.ipv6[14], event.__sock.ipv6[15]);

    snprintf(local_ipv6_str, sizeof(local_ipv6_str),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             event.__sock.local_ipv6_socket_addr[0], event.__sock.local_ipv6_socket_addr[1],
             event.__sock.local_ipv6_socket_addr[2], event.__sock.local_ipv6_socket_addr[3],
             event.__sock.local_ipv6_socket_addr[4], event.__sock.local_ipv6_socket_addr[5],
             event.__sock.local_ipv6_socket_addr[6], event.__sock.local_ipv6_socket_addr[7],
             event.__sock.local_ipv6_socket_addr[8], event.__sock.local_ipv6_socket_addr[9],
             event.__sock.local_ipv6_socket_addr[10], event.__sock.local_ipv6_socket_addr[11],
             event.__sock.local_ipv6_socket_addr[12], event.__sock.local_ipv6_socket_addr[13],
             event.__sock.local_ipv6_socket_addr[14], event.__sock.local_ipv6_socket_addr[15]);

    cJSON_AddStringToObject(eventJson, "ipv6", ipv6_str);
    cJSON_AddStringToObject(eventJson, "local_ipv6_socket_addr", local_ipv6_str);
    cJSON_AddStringToObject(eventJson, "path", event.__sock.path);


    /* File event*/
    char buffer_mtime[64] = {};
    snprintf(buffer_mtime, sizeof(buffer_mtime), "%llu", event.old_mtime);
    cJSON_AddStringToObject(eventJson, "old_mtime", buffer_mtime);
    char buffer_new_mtime[64] = {};
    snprintf(buffer_new_mtime, sizeof(buffer_new_mtime), "%llu", event.new_mtime);
    cJSON_AddStringToObject(eventJson, "new_mtime", buffer_new_mtime);
    char buffer_ctime[64] = {};
    snprintf(buffer_ctime, sizeof(buffer_ctime), "%llu", event.old_ctime);
    cJSON_AddStringToObject(eventJson, "old_ctime", buffer_ctime);
    char buffer_new_ctime[64] = {};
    snprintf(buffer_new_ctime, sizeof(buffer_new_ctime), "%llu", event.new_ctime);
    cJSON_AddStringToObject(eventJson, "new_ctime", buffer_new_ctime);
    char buffer_atime[64] = {};
    snprintf(buffer_atime, sizeof(buffer_atime), "%llu", event.old_atime);
    cJSON_AddStringToObject(eventJson, "old_atime", buffer_atime);
    char buffer_new_atime[64] = {};
    snprintf(buffer_new_atime, sizeof(buffer_new_atime), "%llu", event.new_atime);
    cJSON_AddStringToObject(eventJson, "new_atime", buffer_new_atime);
    char buffer_comm_timestamp[64] = {};
    snprintf(buffer_comm_timestamp, sizeof(buffer_comm_timestamp), "%llu", event.comm_timestamp);
    cJSON_AddStringToObject(eventJson, "comm_timestamp", buffer_comm_timestamp);
    
    cJSON_AddNumberToObject(eventJson, "mode", event.mode);
    cJSON_AddNumberToObject(eventJson, "new_mode", event.new_mode);
    char octalBuffMode[5];
    char octalBuffNewMode[5];
    snprintf(octalBuffMode, sizeof(octalBuffMode), "%04o", permission_bits_octal_old_mode);
    snprintf(octalBuffNewMode, sizeof(octalBuffNewMode), "%04o", permission_bits_octal_new_mode);
    cJSON_AddStringToObject(eventJson, "mode_transformed", octalBuffMode);
    cJSON_AddStringToObject(eventJson, "new_mode_transformed", octalBuffNewMode);
    cJSON_AddNumberToObject(eventJson, "old_uid", event.old_uid);
    cJSON_AddNumberToObject(eventJson, "new_uid", event.new_uid);
    cJSON_AddNumberToObject(eventJson, "old_gid", event.old_gid);
    cJSON_AddNumberToObject(eventJson, "new_gid", event.new_gid);

    cJSON_AddNumberToObject(eventJson, "dev_major", event.dev_major);
    cJSON_AddNumberToObject(eventJson, "dev_minor", event.dev_minor);
    cJSON_AddNumberToObject(eventJson, "dev_major_new", event.dev_major_new);
    cJSON_AddNumberToObject(eventJson, "dev_minor_new", event.dev_minor_new);

    cJSON_AddNumberToObject(eventJson, "rdev_major", event.rdev_major);
    cJSON_AddNumberToObject(eventJson, "rdev_minor", event.rdev_minor);
    cJSON_AddNumberToObject(eventJson, "rdev_major_new", event.rdev_major_new);
    cJSON_AddNumberToObject(eventJson, "rdev_minor_new", event.rdev_minor_new);


    cJSON_AddNumberToObject(eventJson, "is_success", event.was_success);
    cJSON_AddNumberToObject(eventJson, "do_not_update_atime", event.do_not_update_atime);
    cJSON_AddNumberToObject(eventJson, "was_file_created", event.was_file_created);
    cJSON_AddNumberToObject(eventJson, "was_file_modified", event.was_file_modified);


    cJSON_AddNumberToObject(eventJson, "is_sensitive_file", event.is_sensitive_file);
    cJSON_AddNumberToObject(eventJson, "is_symlink", event.is_symlink);
    cJSON_AddNumberToObject(eventJson, "was_suid_changed", event.was_suid_changed);
    cJSON_AddNumberToObject(eventJson, "suid_set", event.suid_set);


    cJSON_AddNumberToObject(eventJson, "suid_cleared", event.suid_cleared);
    cJSON_AddNumberToObject(eventJson, "was_sgid_changed", event.was_sgid_changed);
    cJSON_AddNumberToObject(eventJson, "sgid_set", event.sgid_set);
    cJSON_AddNumberToObject(eventJson, "sgid_cleared", event.sgid_cleared);

    cJSON_AddNumberToObject(eventJson, "was_sticky_changed", event.was_sticky_changed);
    cJSON_AddNumberToObject(eventJson, "sticky_set", event.sticky_set);
    cJSON_AddNumberToObject(eventJson, "sticky_cleared", event.sticky_cleared);
    cJSON_AddNumberToObject(eventJson, "was_permission_changed", event.was_permission_changed);

    cJSON_AddNumberToObject(eventJson, "was_owner_changed", event.was_owner_changed);
    cJSON_AddNumberToObject(eventJson, "was_group_changed", event.was_group_changed);
    cJSON_AddNumberToObject(eventJson, "was_creation_time_changed", event.was_creation_time_changed);
    cJSON_AddNumberToObject(eventJson, "was_access_time_changed", event.was_access_time_changed);

    cJSON_AddNumberToObject(eventJson, "was_modified_time_changed", event.was_modified_time_changed);
    cJSON_AddNumberToObject(eventJson, "is_target_dir_world_writable", event.is_target_dir_world_writable);
    cJSON_AddNumberToObject(eventJson, "is_linked_file_SGID_or_SUID", event.is_linked_file_SGID_or_SUID);
    cJSON_AddNumberToObject(eventJson, "is_linked_to_sensitive_file", event.is_linked_to_sensitive_file);
    cJSON_AddNumberToObject(eventJson, "is_cross_user_link", event.is_cross_user_link);
    cJSON_AddNumberToObject(eventJson, "was_dir_removed", event.was_dir_removed);
    cJSON_AddNumberToObject(eventJson, "is_current_dir_world_writable", event.is_current_dir_world_writable);

    cJSON_AddStringToObject(eventJson, "file_type", event.file_type);
    cJSON_AddStringToObject(eventJson, "file_type_new", event.file_type_new);
    cJSON_AddStringToObject(eventJson, "new_filename", event.new_filename);

    string = cJSON_Print(eventJson);
    if (string == NULL)
    {
        fprintf(stderr, "Failed to print event JSON.\n");
    }

    end:
        cJSON_Delete(eventJson);
        return string;
}

/* Libbpf print filter */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

const char *event_type_to_str(event_type type)
{
    switch (type)
    {
    case EVENT_PROCESS_EXIT:
        return "PROCESS_EXIT";
    case EVENT_FILE_OPEN_AND_WRITE:
        return "FILE_OPEN_AND_WRITE_EXIT";
    case EVENT_FILE_OPEN_AND_READ:
        return "FILE_OPEN_AND_READ_EXIT";
    case EVENT_EXECVE:
        return "EXECVE_ENTER";
    case EVENT_INODE_SETATTR:
        return "INODE_SETATTR";
    case EVENT_INODE_CREATE:
        return "INODE_CREATE";
    case EVENT_INODE_LINK:
        return "INODE_LINK";
    case EVENT_INODE_SYMLINK:
        return "INODE_SYMLINK";
    case EVENT_INODE_MKDIR:
        return "INODE_MKDIR";
    case EVENT_INODE_RMDIR:
        return "INODE_RMDIR";
    case EVENT_INODE_MKNOD:
        return "INODE_MKNOD";
    case EVENT_INODE_RENAME:
        return "INODE_RENAME";
    case EVENT_AUTH:
        return "AUTH";
    case EVENT_PASSWD_CHANGE:
        return "PASSWD_CHANGE";
    case EVENT_CHANGE_USER:
        return "CHANGE_USER";
    case EVENT_SOCKET_CREATION:
        return "SOCKET_CREATION";
    case EVENT_SOCKET_BIND:
        return "SOCKET_BIND";
    case EVENT_SOCKET_CONNECT_OUTBOUND:
        return "SOCKET_CONNECT_OUTBOUND";
    case EVENT_SOCKET_LISTEN:
        return "SOCKET_LISTEN";
    case EVENT_SOCKET_ACCEPT:
        return "SOCKET_ACCEPT";
    default:
        return "UNKNOWN_EVENT";
    }
}

void convert_from_int_to_ipv4(unsigned char* buff, unsigned int ipv4){

    buff[0] = ipv4 & 0xFF;
    buff[1] = (ipv4 >> 8) & 0xFF;
    buff[2] = (ipv4 >> 16) & 0xFF;
    buff[3] = (ipv4 >> 24) & 0xFF;

}

/* Unified print + CSV function */
static void print_event_generic(
    TrackFileChanges event, const char *username, const char *groupname
    ,unsigned int permission_bits_octal_old_mode, unsigned int permission_bits_octal_new_mode,
    char exe[EXE_BUFFER])
{

    const char* event_type = event_type_to_str(event.__generics.evt_type);
    printf("EVENT -> %d\n", event.__generics.evt_type);
    printf("sizeof(TrackFileChanges)= %zu\n", sizeof(TrackFileChanges));

    /*generics*/
    fprintf(csv_file, "%d,%s,", event.__generics.evt_type,event_type);
    fprintf(csv_file, "%u,%u,%s,%s,", event.__generics.uid, event.__generics.gid, username, groupname);
    fprintf(csv_file, "%u,%u,%d,%lld,", event.__generics.pid, event.__generics.ppid, event.__generics.exit_code, event.__generics.duration_ns);
    fprintf(csv_file, "%s,%s,%s,%llu,", event.__generics.comm, exe,event.__generics.filename, event.comm_timestamp);
    /*file metadata*/
    fprintf(csv_file, "%u,%04o,%u,%04o,", event.mode, permission_bits_octal_old_mode, event.new_mode ,permission_bits_octal_new_mode);
    fprintf(csv_file, "%hhu, %hhu,", event.was_success, event.do_not_update_atime);
    fprintf(csv_file, "%u,%u,%u,%u,", event.old_uid, event.new_uid, event.old_gid, event.new_gid);
    // fprintf(csv_file, "%lu, %lu, ", event.old_size, event.new_size);
    fprintf(csv_file, "%llu, %llu,", event.old_mtime, event.new_mtime);
    fprintf(csv_file, "%llu, %llu,", event.old_ctime, event.new_ctime);
    fprintf(csv_file, "%llu, %llu,", event.old_atime, event.new_atime);
    fprintf(csv_file, "%s,%s,", event.file_type, event.file_type_new);

    /* file flags / attributes */
    fprintf(csv_file,
            "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,",
            event.is_sensitive_file,
            event.was_suid_changed, event.suid_set, event.suid_cleared,
            event.was_sgid_changed, event.sgid_set, event.sgid_cleared,
            event.was_sticky_changed, event.sticky_set, event.sticky_cleared);

    fprintf(csv_file,
            // TODO de vazut parametrii
            "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,",
            event.was_permission_changed,
            event.was_owner_changed,
            event.was_group_changed,
            // event.was_size_extended,
            // event.was_size_truncated,
            event.was_creation_time_changed,
            event.was_access_time_changed,
            event.was_modified_time_changed);

    fprintf(csv_file,
            "%hhu,%hhu,%hhu,",
            event.was_file_created,
            event.was_file_modified,
            event.is_target_dir_world_writable);

    /* device and file linkage */
    fprintf(csv_file,
            "%u,%u,%u,%u,%u,%u,%u,%u,",
            event.dev_major, event.dev_major_new,
            event.dev_minor, event.dev_minor_new,
            event.rdev_major, event.rdev_minor,
            event.rdev_major_new, event.rdev_minor_new);
            // event.i_bdev_major, event.i_bdev_minor,
            // event.i_bdev_major_new, event.i_bdev_minor_new,
            // event.is_rdev_bdev_mismatch, event.is_rdev_bdev_mismatch_new);

    fprintf(csv_file,
            "%hhu,%hhu,%hhu,%hhu,%s,%hhu,%hhu,",
            event.is_linked_file_SGID_or_SUID,
            event.is_linked_to_sensitive_file,
            event.is_cross_user_link,
            event.is_symlink,
            event.new_filename,
            event.was_dir_removed,
            event.is_current_dir_world_writable);

    /* authentication section */
    fprintf(csv_file,
            "%hhu,%hhu,%hhu,%hhu,%s,%s,%s,%s,%hhu,",
            event.__auth.is_switching_user,
            event.__auth.is_switching_root,
            event.__auth.is_changing_password,
            event.__auth.is_root_command,
            event.__auth.name,
            event.__auth.rhost,
            event.__auth.rname,
            event.__auth.login_type,
            event.__auth.is_success);

    unsigned char buff[4];
    unsigned char buff_local[4];
    // 255.255.255.255 + \0
    convert_from_int_to_ipv4(buff,event.__sock.ipv4);
    convert_from_int_to_ipv4(buff_local,event.__sock.local_ipv4_socket_addr);
    char ipv4_string[16];
    char ipv4_string_local[16];
    snprintf(ipv4_string, sizeof(ipv4_string), "%d.%d.%d.%d", buff[0],buff[1],buff[2],buff[3]);
    snprintf(ipv4_string_local, sizeof(ipv4_string_local), "%d.%d.%d.%d", buff_local[0],buff_local[1],buff_local[2],buff_local[3]);


    /* socket section */
    fprintf(csv_file,
            "%d,%d,%d,%hu,%s,",
            event.__sock.protocol_family,
            event.__sock.socket_type,
            event.__sock.protocol,
            event.__sock.port,
            ipv4_string);

    char ipv6_str[40] = {0};
    char local_ipv6_str[40] = {0};

    snprintf(ipv6_str, sizeof(ipv6_str),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             event.__sock.ipv6[0], event.__sock.ipv6[1], event.__sock.ipv6[2], event.__sock.ipv6[3],
             event.__sock.ipv6[4], event.__sock.ipv6[5], event.__sock.ipv6[6], event.__sock.ipv6[7],
             event.__sock.ipv6[8], event.__sock.ipv6[9], event.__sock.ipv6[10], event.__sock.ipv6[11],
             event.__sock.ipv6[12], event.__sock.ipv6[13], event.__sock.ipv6[14], event.__sock.ipv6[15]);

    snprintf(local_ipv6_str, sizeof(local_ipv6_str),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             event.__sock.local_ipv6_socket_addr[0], event.__sock.local_ipv6_socket_addr[1],
             event.__sock.local_ipv6_socket_addr[2], event.__sock.local_ipv6_socket_addr[3],
             event.__sock.local_ipv6_socket_addr[4], event.__sock.local_ipv6_socket_addr[5],
             event.__sock.local_ipv6_socket_addr[6], event.__sock.local_ipv6_socket_addr[7],
             event.__sock.local_ipv6_socket_addr[8], event.__sock.local_ipv6_socket_addr[9],
             event.__sock.local_ipv6_socket_addr[10], event.__sock.local_ipv6_socket_addr[11],
             event.__sock.local_ipv6_socket_addr[12], event.__sock.local_ipv6_socket_addr[13],
             event.__sock.local_ipv6_socket_addr[14], event.__sock.local_ipv6_socket_addr[15]);

    fprintf(csv_file,
            "%s,",
            ipv6_str);

    fprintf(csv_file, "%hu,%s,", event.__sock.local_socket_port, ipv4_string_local);

    fprintf(csv_file,
            "%s,",
            local_ipv6_str);

    fprintf(csv_file,
            "%s,%d,%d,%d,%d,%d,%hhu,%hhu,%hhu,",
            event.__sock.path,
            event.__sock.peer_pid,
            event.__sock.peer_uid,
            event.__sock.peer_gid,
            event.__sock.backlog_value,
            event.__sock.ifindex,
            event.__sock.kernel_sock,
            event.__sock.is_important_port,
            event.__sock.is_success);

    /* Print argv separately */
    if (event.__generics.argv)
    {
        fprintf(csv_file, "\""); 
        
        for (int i = 0; i < MAX_ARGS_CAPTURED; i++)
        {
            if (event.__generics.argv[i][0] == '\0')
                break;
            fprintf(csv_file, "%s ", event.__generics.argv[i]); 
        }

        // Close the quote and add the final newline
        fprintf(csv_file, "\"\n"); 
    } else {
        // If there are no args, just print an empty quoted string and the newline
        fprintf(csv_file, "\"\n");
    }
    fflush(csv_file);
    return;
}


// =============================================================
// PATH RESOLUTION LOGIC (Without FD Scanning)
// =============================================================

// PHASE 1: Map Major:Minor to Mount Point
int get_mount_point(unsigned int maj, unsigned int min, char *mnt_buf, size_t mnt_len) {
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) return 0;

    char *line = NULL;
    size_t len = 0;
    int found = 0;
    
    while (getline(&line, &len, fp) != -1) {
        unsigned int m_maj, m_min;
        char mount_point[MAX_RESOLVE_PATH];
        
        // Parsing layout of mountinfo
        // We look for the column with Maj:Min and the mount path
        if (sscanf(line, "%*d %*d %u:%u %*s %s", &m_maj, &m_min, mount_point) == 3) {
            if (m_maj == maj && m_min == min) {
                strncpy(mnt_buf, mount_point, mnt_len);
                mnt_buf[mnt_len - 1] = '\0';
                found = 1;
                break;
            }
        }
    }

    free(line);
    fclose(fp);
    return found;
}

// PHASE 2: Recursive Search with SAFE DEVICE CHECK (find -xdev style)
int recursive_search(const char *base_path, const char *target_name, 
                     unsigned long target_inode, dev_t target_dev, 
                     char *result_path) {
    
    DIR *dir = opendir(base_path);
    if (!dir) return 0;

    const char *fmt = (strcmp(base_path, "/") == 0) ? "%s%s" : "%s/%s";

    struct dirent *entry;
    char path[MAX_RESOLVE_PATH];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // 1. FAST MATCH: Check Filename first (Avoids syscalls)
        if (strcmp(entry->d_name, target_name) == 0) {
            // 2. VERIFY MATCH: Check Inode
            if (entry->d_ino == target_inode) {
                snprintf(result_path, MAX_RESOLVE_PATH, fmt, base_path, entry->d_name);
                closedir(dir);
                return 1; // FOUND!
            }
        }

        // 3. RECURSE: Only if directory AND on the same device
        if (entry->d_type == DT_DIR) {
            snprintf(path, sizeof(path), fmt, base_path, entry->d_name);
            
            // --- CRITICAL SAFETY CHECK ---
            // We stat the directory before entering.
            // If the directory belongs to a different device (mount point), we SKIP it.
            struct stat sb;
            if (stat(path, &sb) == 0) {
                if (sb.st_dev != target_dev) {
                    continue; // Skip mount points / other disks
                }
            } else {
                continue; // Cannot access, skip
            }

            // Dive in
            if (recursive_search(path, target_name, target_inode, target_dev, result_path)) {
                closedir(dir);
                return 1;
            }
        }
    }

    closedir(dir);
    return 0;
}

// MASTER RESOLVER FUNCTION
int resolve_complete_path(unsigned int pid, const char *filename,
                          unsigned int major, unsigned int minor, unsigned long inode,
                          char *out_path, size_t out_size)
{
    // 0. Validity checks
    if (!filename || strcmp(filename, "void") == 0) return -1;
    
    // 0. If it's already absolute, just return it
    if (filename[0] == '/') {
        strncpy(out_path, filename, out_size - 1);
        out_path[out_size - 1] = '\0';
        return 0;
    }

    // --- STRATEGY: MOUNT POINT SEARCH (Cold Search) ---
    
    // 1. Map the Device ID (from eBPF) to a folder (e.g., /home)
    char mount_point[MAX_RESOLVE_PATH];
    if (get_mount_point(major, minor, mount_point, sizeof(mount_point))) {
        
        dev_t target_dev = makedev(major, minor);
        
        // 2. Search inside that folder for Name + Inode
        // This is safe because recursive_search checks device boundaries
        if (recursive_search(mount_point, filename, inode, target_dev, out_path)) {
             return 0; // Success
        }
    }

    // Total Failure
    snprintf(out_path, out_size, "unresolved/%s", filename);
    return -1;
}


int resolve_full_exe(unsigned int pid,char *out_exe, size_t out_size_exe){


    char cwd_link_exe[EXE_BUFFER];
    char cwd_exe[EXE_BUFFER];
    ssize_t len;

    snprintf(cwd_link_exe, sizeof(cwd_link_exe), "/proc/%u/exe", pid);
    len = readlink(cwd_link_exe, cwd_exe, sizeof(cwd_exe) - 1);
    if (len == -1)
    {
        snprintf(out_exe, out_size_exe, "void");
        return -1;
    }

    cwd_exe[len] = '\0';
    snprintf(out_exe, out_size_exe, "%s", cwd_exe);
    return 0;

}

void load_sensitive_files(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        perror("Failed to open sensitive_files.txt");
        return;
    }
    
    char buf[MAX_PATH_LEN];
    while (fgets(buf, sizeof(buf), fp))
    {
        buf[strcspn(buf, "\n")] = '\0'; // remove newline
        if (sensitive_count < MAX_SENSITIVE)
        {
            strncpy(sensitive_list[sensitive_count], buf, sizeof(sensitive_list[0]) - 1);
            sensitive_list[sensitive_count][sizeof(sensitive_list[0]) - 1] = '\0';
            sensitive_count++;
        }
    }
    fclose(fp);
}

unsigned char is_sensitive_file(const char *filename)
{
    int pid = getpid();
    if (!filename || filename[0] == '\0')
        return -1;

    for (int i = 0; i < sensitive_count; i++)
    {
        const char *pattern = sensitive_list[i];

        // Check for prefix match (directory)
        if (strncmp(filename, pattern, strlen(pattern)) == 0)
            return 1;

        // Optional: check if pattern is contained anywhere
        if (strstr(filename, pattern))
            return 1;
    }
    return 0;
}


static int handle_event(void *ctx, void *data, size_t sa)
{
    const TrackFileChanges *event = (TrackFileChanges *)data;
    
    struct passwd *pw;
    struct group *gr;

    TrackFileChanges local_event;
    memcpy(&local_event, event, sizeof(*event));

    
    // printf("EVENT TYPE %s\n", event_type_to_str(local_event.__generics.evt_type));

    // --- Resolve usernames / groupnames ---
    pw = getpwuid(local_event.__generics.uid);
    gr = getgrgid(local_event.__generics.gid);
    const char *username = pw ? pw->pw_name : "unknown";
    const char *groupname = gr ? gr->gr_name : "unknown";

    // not added yet, to be added ( depends )
    pw = getpwuid(local_event.old_uid);
    gr = getgrgid(local_event.old_gid);
    const char *old_username = pw ? pw->pw_name : "unknown";
    const char *old_groupname = gr ? gr->gr_name : "unknown";
    // ----------------------------

    // not added yet, to be added ( depends )
    pw = getpwuid(local_event.new_uid);
    gr = getgrgid(local_event.new_gid);
    const char *new_username = pw ? pw->pw_name : "unknown";
    const char *new_groupname = gr ? gr->gr_name : "unknown";
    // ----------------------------

    // --- Resolve full path for filename ---
    char full_path[FILENAME_MAX];
    char full_path_new[FILENAME_MAX];
    if (strcmp(local_event.__generics.filename, local_event.new_filename) == 0){
        if (resolve_complete_path(local_event.__generics.pid,
                                    local_event.__generics.filename,
                                    local_event.dev_major,
                                    local_event.dev_minor,
                                    local_event.inode_number, 
                                    full_path, sizeof(full_path)) == 0)
            {
                // Copy the resolved path back to the event
                strncpy(local_event.__generics.filename, full_path,
                        sizeof(local_event.__generics.filename) - 1);
                local_event.__generics.filename[sizeof(local_event.__generics.filename) - 1] = '\0';
                // also to the new_file name
                strncpy(local_event.new_filename, full_path,
                        sizeof(local_event.new_filename) - 1);
                local_event.new_filename[sizeof(local_event.new_filename) - 1] = '\0';
                
            }
    }else{
        if (resolve_complete_path(local_event.__generics.pid,
                                    local_event.__generics.filename,
                                    local_event.dev_major,
                                    local_event.dev_minor,
                                    local_event.inode_number, 
                                    full_path, sizeof(full_path)) == 0)
            {
                // Copy the resolved path back to the event
                strncpy(local_event.__generics.filename, full_path,
                        sizeof(local_event.__generics.filename) - 1);
                local_event.__generics.filename[sizeof(local_event.__generics.filename) - 1] = '\0';
            }
        if (resolve_complete_path(local_event.__generics.pid,
                                    local_event.new_filename,
                                    local_event.dev_major_new,
                                    local_event.dev_minor_new,
                                    local_event.inode_number_new, 
                                    full_path, sizeof(full_path_new)) == 0)
            {
                strncpy(local_event.new_filename, full_path_new,
                        sizeof(local_event.new_filename) - 1);
                local_event.new_filename[sizeof(local_event.new_filename) - 1] = '\0';
            }
    }

    
    char exe[EXE_BUFFER];
    

    if (resolve_full_exe(local_event.__generics.pid,exe,sizeof(exe)) != 0)
    {
        printf("Did not manage to get exe\n");
    }

    unsigned int permission_bits_octal_old_mode = local_event.mode & MODE_MASK;
    unsigned int permission_bits_octal_new_mode = local_event.new_mode & MODE_MASK;

    unsigned char check_is_sensitive_file = is_sensitive_file(local_event.__generics.filename);
    if (check_is_sensitive_file == 1)
    {
        local_event.is_sensitive_file = 1;
    }
    else if (check_is_sensitive_file == 0)
    {
        local_event.is_sensitive_file = 0;
    }
    else
    {
        local_event.is_sensitive_file = -1;
    }
    // de verificat aici doar daca e event de symlink
    if (local_event.__generics.evt_type == EVENT_INODE_SYMLINK){
        unsigned char check_is_linked_to_sensitive_file = is_sensitive_file(local_event.new_filename);
        if (check_is_linked_to_sensitive_file == 1)
        {
            local_event.is_linked_to_sensitive_file = 1;
        }
        else if (check_is_linked_to_sensitive_file == 0)
        {
            local_event.is_linked_to_sensitive_file = 0;
        }
    }else
    {
        local_event.is_linked_to_sensitive_file = -1;
    }

    char* stringJson = createJson(local_event, username, groupname, permission_bits_octal_old_mode, permission_bits_octal_new_mode, exe);
    issueCommand(client, "XADD", "file_events", stringJson);
    free(stringJson);
    // --- Print event data ---
    print_event_generic(local_event, username, groupname, permission_bits_octal_old_mode, permission_bits_octal_new_mode, exe);
    // print_event_generic(local_event, username, groupname);


    return 0;
}


int update_map(struct bpf_map *map,
               const void *key, size_t key_size,
               const void *val, size_t val_size)
{
    return bpf_map__update_elem(map,
                                key, key_size,
                                val, val_size,
                                BPF_ANY);
}

struct bpf_map *select_map_by_name(void *skel, char skel_type, const char *map_name)
{
    if (skel_type == 'f') {
        struct file_ebpf *s = skel;

        if (!strcmp(map_name, "comm_filtering"))      return s->maps.comm_filtering;
        if (!strcmp(map_name, "blocked_filenames"))   return s->maps.blocked_filenames;
        if (!strcmp(map_name, "blocked_patterns"))    return s->maps.blocked_patterns;

    }
    else if (skel_type == 's') {
        struct socket_ebpf *s = skel;

        if (!strcmp(map_name, "socket_comm_filtering")) return s->maps.socket_comm_filtering;

    }else if (skel_type == 'e') {
        struct ebpf *e = skel;
        if (!strcmp(map_name, "blocked_comms_from_filenames")) return e->maps.blocked_comms_from_filenames;
    }

    return NULL; // Not found
}

int *select_global_counter(const char *map_name)
{
    if (!strcmp(map_name,"socket_comm_filtering")) return &blocked_socket_command_count;
    if (!strcmp(map_name,"blocked_patterns"))      return &blocked_patterns_count;
    if (!strcmp(map_name,"comm_filtering"))        return &blocked_comm_count;
    if (!strcmp(map_name,"blocked_filenames"))     return &blocked_filenames_count;
    if (!strcmp(map_name,"blocked_comms_from_filenames"))     return &blocked_comms_from_filenames_count;
    
    return NULL;
}

static inline int update_map_generic(struct bpf_map *map, void *key, size_t key_size, void *value, size_t value_size)
{
    return bpf_map__update_elem(map, key, key_size, value, value_size, BPF_ANY);
}



void load_into_maps(void *skel, const char *filename, int map_max_entries, int key_size, int value_size, char skel_type, const char *map_name, int is_array)
{
    struct bpf_map *map = select_map_by_name(skel, skel_type, map_name);
    if (!map) {
        fprintf(stderr, "Unknown map: %s\n", map_name);
        return;
    }

    int *global_count = select_global_counter(map_name);
    if (!global_count) {
        fprintf(stderr, "No global counter found for map: %s\n", map_name);
        return;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open <%s>\n", filename);
        return;
    }

    char buf[4096]; // Generic buffer
    int index = *global_count;

    while (fgets(buf, sizeof(buf), fp)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] == '\0') continue;

        if (index >= map_max_entries) break;

        int ret;
        if (is_array) {
            uint32_t array_index = index;
            char val[value_size];
            memset(val, 0, sizeof(val));
            strncpy(val, buf, sizeof(val)-1);
            ret = update_map_generic(map, &array_index, sizeof(array_index), val, sizeof(val));
        } else {
            char key[key_size];
            memset(key, 0, sizeof(key));
            strncpy(key, buf, sizeof(key)-1);
            ret = update_map_generic(map, key, sizeof(key), &blocked, sizeof(blocked));
        }

        if (ret)
            fprintf(stderr, "Failed to insert key/element [%s] into map %s\n", buf, map_name);

        index++;
    }

    *global_count = index;
    fclose(fp);
}

/* MAIN */
int main(void)
{
    libbpf_set_print(libbpf_print_fn);
    setenv("LIBBPF_DEBUG", "1", 1);

    /* CSV setup */
    csv_file = fopen("events.csv", "w");
    if (!csv_file)
    {
        perror("Failed to open events.csv for writing");
        return 1;
    }

    load_sensitive_files("sensitive_files.txt");

    fprintf(csv_file,
            "event_type,event_type_str,"
            "uid,gid,username,groupname,"
            "pid,ppid,exit_code,durations_ns,"
            "comm,exe,filename,comm_timestamp,"
            /* FILE DATA CHANGED */
            "mode,mode_transformed,new_mode,new_mode_transformed,is_success,do_not_update_atime,"
            "old_uid,new_uid,old_gid,new_gid,"
            "old_mtime,new_mtime,"
            "old_ctime,new_ctime,"
            "old_atime,new_atime,"
            "file_type,file_type_new,"
            "is_sensitive_file,"
            "was_suid_changed,suid_set,suid_cleared,"
            "was_sgid_changed,sgid_set,sgid_cleared,"
            "was_sticky_changed,sticky_set,sticky_cleared,"
            "was_permission_changed,"
            "was_owner_changed,"
            "was_group_changed,"
            "was_creation_time_changed,"
            "was_access_time_changed,"
            "was_modified_time_changed,"
            "was_file_created,was_file_modified,"
            "is_target_dir_world_writable,"
            "dev_major,dev_major_new,dev_minor,dev_minor_new,"
            "rdev_major,rdev_minor,rdev_major_new,rdev_minor_new,"
            "is_linked_file_SGID_or_SUID,is_linked_to_sensitive_file,"
            "is_cross_user_link,"
            "is_symlink,"
            "new_filename,"
            "was_dir_removed,"
            "is_current_dir_world_writable,"
            /* AUTH DATA */
            "is_switching_user,is_switching_root,"
            "is_changing_password,is_root_command,"
            "name,rhost,rname,login_type,"
            "is_auth_success,"
            /* SOCKET DATA */
            "protocol_family,socket_type,protocol,"
            "port,ipv4,ipv6,"
            "local_socket_port,local_ipv4_socket_addr,local_ipv6_socket_addr,"
            "path,"
            "peer_pid,peer_uid,peer_gid,"
            "backlog,ifindex,"
            "kernel_sock,is_important_port,is_sock_success,"
            "argv\n");

    fflush(csv_file);

    /*
        1.*****************LOAD THE SKELETONS*************************
    */
    struct file_ebpf *file_skel = file_ebpf__open();
    if (!file_skel)
    {
        fprintf(stderr, "Failed to open file events skeleton\n");
        return 1;
    }

    struct ebpf *execve_skel = ebpf__open();
    if (!execve_skel){
        fprintf(stderr, "Failed to open execve_skel\n");
        return 1;
    }

    struct process_events_ebpf *proc_skel = process_events_ebpf__open();
    if (!proc_skel){
        fprintf(stderr, "Failed to open process_events skeleton\n");
        return 1;
    }

    struct auth_ebpf* auth_skel = auth_ebpf__open();
    if (!auth_skel){
        fprintf(stderr, "Failed to open auth events skeleton\n");
        return 1;
    }


    struct socket_ebpf* socket_skel = socket_ebpf__open();
    if (!socket_skel){
        fprintf(stderr, "Failed to open socket events skeleton\n");
        return 1;
    }

    /*
        2.*****************LOAD ONLY THE OWNER SKELETON *************************
    */

    if (file_ebpf__load(file_skel)) {
        fprintf(stderr, "Failed to load file_ebpf skeleton\n");
        goto cleanup;
    }

    /*
        3.*****************EXTRACT THE MAPS FILE DESCRIPTORS *************************
    */

    int ring_buffer_fd        = bpf_map__fd(file_skel->maps.file_events);
    int blocked_patterns_fd   = bpf_map__fd(file_skel->maps.blocked_patterns);
    int self_pid_fd           = bpf_map__fd(file_skel->maps.self_pid);
    int comm_filtering_fd     = bpf_map__fd(file_skel->maps.comm_filtering);
    int active_file_pids_fd   = bpf_map__fd(file_skel->maps.active_file_pids);
    int blocked_patterns_pids_fd = bpf_map__fd(file_skel->maps.blocked_patterns_pids);
    int blocked_filenames_fd = bpf_map__fd(file_skel->maps.blocked_filenames);



    fprintf(stdout, "FILE_EVENTS FD: %d\n", ring_buffer_fd);
    fprintf(stdout, "SELF_PID FD: %d\n", self_pid_fd);
    fprintf(stdout, "COMM_FILTER FD: %d\n", comm_filtering_fd);
    fprintf(stdout, "ACTIVE_FILE_PIDS FD: %d\n", active_file_pids_fd);
    fprintf(stdout, "BLOCKED_PATTERNS_PIDS FD: %d\n", blocked_patterns_pids_fd);
    fprintf(stdout, "BLOCKED_FILENAMES FD: %d\n", blocked_filenames_fd);


    /*
     * 4.************************REUSE FILE_SKELETON MAP FDs ON OTHER SKELETONS (BEFORE LOAD) *************************
     */

    // execve_skel
    bpf_map__reuse_fd(execve_skel->maps.file_events, ring_buffer_fd);
    bpf_map__reuse_fd(execve_skel->maps.self_pid,    self_pid_fd);
    bpf_map__reuse_fd(execve_skel->maps.comm_filtering, comm_filtering_fd);
    bpf_map__reuse_fd(execve_skel->maps.blocked_filenames, blocked_filenames_fd);


    // proc_skel
    bpf_map__reuse_fd(proc_skel->maps.file_events, ring_buffer_fd);
    bpf_map__reuse_fd(proc_skel->maps.self_pid,    self_pid_fd);
    bpf_map__reuse_fd(proc_skel->maps.comm_filtering, comm_filtering_fd);
    bpf_map__reuse_fd(proc_skel->maps.active_file_pids, active_file_pids_fd);
    bpf_map__reuse_fd(proc_skel->maps.blocked_patterns_pids, blocked_patterns_pids_fd);


    // auth_skel
    bpf_map__reuse_fd(auth_skel->maps.file_events, ring_buffer_fd);
    bpf_map__reuse_fd(auth_skel->maps.self_pid,    self_pid_fd);
    bpf_map__reuse_fd(auth_skel->maps.comm_filtering, comm_filtering_fd);

    // sock_skel
    bpf_map__reuse_fd(socket_skel->maps.file_events, ring_buffer_fd);
    bpf_map__reuse_fd(socket_skel->maps.comm_filtering, comm_filtering_fd);
    bpf_map__reuse_fd(socket_skel->maps.self_pid,    self_pid_fd);
    bpf_map__reuse_fd(socket_skel->maps.blocked_patterns, blocked_patterns_fd);


    /*
     * ───────────────────────────────────────────────
     * 5. LOAD THE OTHER SKELETONS (NOW THEY SHARE MAPS)
     * ───────────────────────────────────────────────
     */
    if (ebpf__load(execve_skel)) {
        fprintf(stderr, "Failed to load execve skeleton\n");
        goto cleanup;
    }

    if (process_events_ebpf__load(proc_skel)) {
        fprintf(stderr, "Failed to load process_events skeleton\n");
        goto cleanup;
    }

    if (auth_ebpf__load(auth_skel)) {
        fprintf(stderr, "Failed to load auth skeleton\n");
        goto cleanup;
    }

    if (socket_ebpf__load(socket_skel)) {
        fprintf(stderr, "Failed to load socket skeleton\n");
        goto cleanup;
    }


    // ************** Continue
    // filter_logs_conditions(file_skel);
    // load file_skel - blocked_filenames
    load_into_maps(file_skel,"blocked_filenames.txt",1024,MAX_CHAR_LEN, sizeof(__u8), 'f' , "blocked_filenames", 0);
    // load file_skel - blocked_comm_names
    load_into_maps(file_skel,"blocked_comm_names.txt",128,TYPE, sizeof(__u8), 'f' , "comm_filtering", 0);
    // load into execve_skell - blocked_coms_from_filames
    load_into_maps(execve_skel,"blocked_comm_names_from_filenames.txt",256,TYPE_3, sizeof(__u8), 'e' , "blocked_comms_from_filenames", 0);
    // load file_skel - blocked_patterns
    load_into_maps(file_skel, "blocked_patterns.txt", LITTLE_MAP_SIZE, sizeof(uint32_t), MAX_PATTERN_LEN, 'f', "blocked_patterns", 1);
    // load socket_skel - blocked_comm
    load_into_maps(socket_skel, "blocked_comm_names_sockets.txt", 128, TYPE, sizeof(__u8), 's', "socket_comm_filtering", 0);

    /*
        7. ***************LOAD ALL THE PROGRAMS******************
    */
    if (file_ebpf__attach(file_skel))
    {
        fprintf(stderr, "Failed to attach file events skeleton\n");
        goto cleanup;
    }

    if (ebpf__attach(execve_skel)){
        fprintf(stderr, "Failed to attach execve skeleton\n");
        goto cleanup;
    }

    if (process_events_ebpf__attach(proc_skel)){
        fprintf(stderr, "Failed to attach process exit events skeleton\n");
        goto cleanup;
    }

    if (auth_ebpf__attach(auth_skel)){
        fprintf(stderr, "Failed to attach auth skeleton\n");
        goto cleanup;
    }

    if (socket_ebpf__attach(socket_skel)){
        fprintf(stderr, "Failed to attach socket skeleton\n");
        goto cleanup;
    }

    // Connect to redis
    client = connectToRedisServer("127.0.0.1", redisPort);

    if (client == NULL){
        fprintf(stderr, "Could not connect to redis server\n");
        return 1;
    }

    // GET THE BUFFER
    struct ring_buffer *file_events = ring_buffer__new(ring_buffer_fd,handle_event, NULL, NULL);

    int pid = getpid();
    printf("Current PID: %d\n", pid);
    sleep(1);

    __u32 key = 0;
    if (bpf_map__update_elem(file_skel->maps.self_pid, &key, sizeof(key), &pid, sizeof(pid), BPF_ANY) < 0)
    {
        perror("bpf_map_update_elem failed");
        goto cleanup;
    }

    for (;;)
    {
        ring_buffer__poll(file_events, 100);

    }

cleanup:
    if (csv_file)
        fclose(csv_file);

    if (file_events)
        ring_buffer__free(file_events);
    
    if (client)
        redisFree(client);

    file_ebpf__destroy(file_skel);
    ebpf__destroy(execve_skel);
    process_events_ebpf__destroy(proc_skel);
    auth_ebpf__destroy(auth_skel);
    socket_ebpf__destroy(socket_skel);


    return 0;
}
