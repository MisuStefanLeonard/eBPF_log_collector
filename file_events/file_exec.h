#ifndef __FILE_EXEC_H__
#define __FILE_EXEC_H__

// #include <linux/stat.h>
#include "../utils/utils.h"

// /*sys_enter_openat*/
// typedef struct TrackFileOpening
// {
//     Generics __generics;
//     long long unsigned int flags;
//     long long unsigned int mode;
// } TrackFileOpening;

typedef struct
{
    unsigned int evt_type;
    unsigned int uid;
    unsigned int gid;
    unsigned int pid;
    unsigned int ppid;
    unsigned int exit_code;
    unsigned char wasWriteSuccesfull;
    char comm[64];
    char filename[FILE_NAME_LEN];
} TrackFileWrite;

// /*sys_enter_openat2*/
// typedef struct TrackFileOpening2
// {
//     unsigned int evt_type;
//     unsigned int uid;
//     unsigned int gid;
//     unsigned int pid;
//     unsigned int ppid;
//     unsigned int exit_code;
//     char comm[64];
//     char filename[FILE_NAME_LEN];
//     long long unsigned int flags;
//     long long unsigned int mode;
//     long long unsigned int resolve;
//     // struct open_how how;
// } TrackFileOpening2;

// /*sys_enter_read*/
// typedef struct TrackFileRead
// {
//     unsigned int evt_type;
//     unsigned int uid;
//     unsigned int gid;
//     unsigned int pid;
//     unsigned int ppid;
//     unsigned int exit_code;
//     char comm[64];
//     int file_desc;
// } TrackFileRead;


// __attribute__((aligned(8)))
#endif // FILE_EXEC.H