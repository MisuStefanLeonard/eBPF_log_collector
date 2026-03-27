# STEPS

## 1. eBPF installation

( if you want to see the .elf or dissasembly with bpftool and to set permissions on eBPF programs e.g only ADMIN capabilities or ROOT, run this, ((--HERE it is not needed--)) , than continue with the rest)

```bash
sudo apt-get update
sudo apt install git build-essential clang llvm libbpf-dev libssl-dev libcap-dev binutils-dev
```

### Installation

```bash
sudo apt-get update
sudo apt install git build-essential clang llvm libbpf-dev libssl-dev
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
sudo make install
bpftool version
```

### CHECK LSM AVALIBILITY ( Linux 5.7+ integration with eBPF) (if u see this, you're good, else GO TO 3.)

```bash
sudo -i ( change to root )

cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y

cat /sys/kernel/security/lsm; echo
lockdown,capability,yama,apparmor,bpf
```

### ADD LSM (3.)

```bash
sudo nano /etc/default/grub
### ADD THIS: GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf" ###
update-grub
```

### CLONE REPO

```bash
git clone https://github.com/MisuStefanLeonard/licenta_start.git
mkdir vmlinux
cd vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
cd ..
make
```

## 2. Redis Stack installation

### Install redis stack (taken from docs)

```bash
sudo apt-get install lsb-release curl gpg
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt-get install redis-stack-server
```

### Ubuntu >= 22.04

#### Step 1

```bash
sudo nano /etc/apt/source.list.d/redis.list
```

#### Step 2

- Replace `noble` (or on what ubuntu version you are) and put `jammy` (latest usable version)

### Start the service

```bash
sudo systemctl enable redis-stack-server
sudo systemctl start redis-stack-server
```

### Installing redis client for C

#### 1. Go to [redis](https://github.com/redis/hiredis)

#### 2. Clone and go to redis folder and run make

```bash
git clone https://github.com/redis/hiredis
cd hiredis
sudo make install
```

### 3. cJSON library installation (taken from docs)

#### 1. Clone repo

```bash
git clone https://github.com/DaveGamble/cJSON
```

#### 2. Compile and build using CMake

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

## 4. Official documentation

### **_Part I_**

- **So what is this eBPF** ? **How it works ?** **Why only on linux OS ?**
- These are a few questions I asked myself.

  #### I. What is eBPF ? How it works ?
  - eBPF is an open-source project maintained by the community
  - It is build on top of the **linux OS** which enables the users to write programs on kernel level
  - Write programs on kernel level ??? So I can track what I want ? **EXACTLY!**
  - But that means that the programs we write must be **safe** from the view point of **the kernel**, so that can be pretty restrictive. **Well, yes and no in the same time.**
  - Yes because, for example, if our program has too many instructions, the kernel verifier will throw us an error (even thought in the current version of eBPF, you can bypass this). Or if you try to access some protected memory in your own way, (e.g `struct socket`) and you do not do it using specific built-ins from eBPF (which are verifier **_SAFE_**), it will **_NOT_** pass the verifier.
  - No, because **WE CAN ATTACH PROGRAMS ON KERNEL LEVEL**, so that is pretty powerfull. We'll get into further details in the next lines.
  - Imagine you got a house. You can have cameras that watch everything on the hallway, in the rooms , in the your yard etc. But what if you want a mini-camera inside a drawer where you keep your money? Or maybe you want a camera under the bed ? This is how eBPF works. You can attach cameras everywhere.
  - From the room itself (e.g `sys_enter_execve` syscall) to the `pam_authenticate` function.
  - They get attached as an `instruction` on where you want it to be attached. So when an `execve` is called , the eBPF program is also called and you get your information into the `userspace`.
  - The `userspace` is the part on where you write the code . Mostly the code is written in pure C and compiled with `LLVM` , but not the only way! What a flexibility. Guess what. If you are not a C enjoyer, than you can write your code in `Go` or `Python`.
  - The powerfull architecture of eBPF is that the `kernel` can communicate with the `userspace` through `maps`. We'll get into further details later.
  - Besides tracing, you can also mitigate attacks via the **_Linux Security Module_** or **_LSM_**. The eBPF permits program's attaching to the **_LSM_** hooks. Here are a few examples of the hooks I used in this project.

  ```c
  /* Hooks that target file interaction */
  /* SEC comes from Section, this is where they get attached */
  SEC("lsm/file_open")
  SEC("lsm/inode_setattr")
  SEC("lsm/inode_create")
  SEC("lsm/inode_link")
  SEC("lsm/inode_symlink")
  SEC("lsm/inode_mkdir")
  SEC("lsm/inode_rmdir")
  SEC("lsm/inode_mknod")
  SEC("lsm/inode_rename")
  /* Hooks that target socket interaction */
  SEC("lsm/socket_accept")
  SEC("lsm/socket_listen")
  SEC("lsm/socket_connect")
  SEC("lsm/socket_bind")
  SEC("lsm/socket_create")
  ```

  - So what I am saying with this is that if you have some set of **rules**, based on those rules you can stop the commands before they do something to the system, but this can be pretty stiff. Eh, you cannot have them all!
  - We'll cover more of this in the next sections.

  #### II. Why only on linux OS ?
  - Because of it's architecture. eBPF is literally a **subsystem** physically built into the **linux kernel**. But there are some good news for the windows users, Microsoft is actually trying to port it to windows also because of it's extrem good capabilities and large horizon and what it can do

### **_Part II_**

- One of the best things that eBPF has, it's the portability of it. What do you mean with portability ?
- What I mean with portability is that if I am sitting on `Ubuntu 24.04` with a linux kernel version of `6.8` and you are sitting on something older, it is **_ALMOST ( 95% )_** portable because of `BPF CO-RE`.
- Ok that seems pretty wow. How `CO-RE` works exactly and what it means.
- `CO-RE (Compile Once, Run Everywhere)` is the BPF capability to generate the internal system structs (`struct socket`, `struct file`) based on the system you have, even though it must be adapted to older versions, with very much simplicity.
- **_IMPORTANT NOTE : Because I am using the `LSM` hooks , linux kernel version must be `5.7+` So if you decide to use the `LSM` hooks, your version must be 5.7+ and your system to have the `LSM capability`._**
- **BPF CO-RE generated a `vmlinux.h` file. It will be 100k+ lines of the internal system structs of your own system. From there, you can access them in your eBPF programs.**
- As you saw in the installation steps, this program was made on `Ubuntu 24.04` with a version of `6.8` on kernel version.
- **_THIS MUST BE ADAPTED FOR OLDER VERSION, OR NEWER ( FUTURE WORK )_**

  #### 1. File Structure

  ```bash
  ├── auth_calls // the UPROBES (will get into details futher down) atached to the functions
  │   ├── auth.c // the main code
  │   ├── auth_ebpf.skel.h // the skeleton of eBPF
  │   └── auth.h // header
  // These are the custom *rules* I added because the logging was too *noisy*
  ├── blocked_comm_names_from_filenames.txt
  ├── blocked_comm_names_sockets.txt
  ├── blocked_comm_names.txt
  ├── blocked_filenames.txt
  ├── blocked_patterns_from_commands_sockets.txt
  ├── blocked_patterns.txt
  // Main entry and connection of the eBPF programs
  ├── exec.c
  // Tracing program attached to *execve* system call
  ├── execve_called
  │   ├── ebpf.c
  │   ├── exec.h
  │   └── exec.skel.h
  // Tracing program attached to the *LSM* hooks for file interaction
  ├── file_events
  │   ├── file_ebpf.c
  │   ├── file_exec.h
  │   └── file_open.skel.h
  ├── LICENSE
  ├── Makefile
  // Tracing program attached to the process exit system call
  ├── process_events
  │   ├── process_ebpf.c
  │   ├── process_exec.h
  │   └── process_exec.skel.h
  ├── README.md
  // The redis logic for sending the data to the ML algorithm
  ├── redis
  │   ├── redislogic.c
  │   └── redislogic.h
  // The scripts that I run to get the logs
  // The filter_logs_2.txt was ran in sandbox docker container , each command in terminal via a .py script
  ├── scripts
  │   ├── cron_miner.sh
  │   ├── exfiltration.sh
  │   ├── fake_device_and_hidden_data.sh
  │   ├── filter_logs_2.txt
  │   ├── hijack.sh
  │   ├── link_attack_with_pass.sh
  │   ├── log_collector.sh
  │   ├── log_wiper.sh
  │   ├── perm_tamper.sh
  │   ├── ransowmare.sh
  │   ├── shadow_user.sh
  │   ├── ssh_keytampering.sh
  │   ├── SUID_privillege_escalation.sh
  │   ├── user_hunter.sh
  │   └── watcher.sh
  // On what data I trained the model ( without the 1.csv)
  ├── scripts_results
  │   ├── 1.csv
  │   ├── beroot.csv
  │   ├── cron_job_with_network.csv
  │   ├── cron_job_without_network.csv
  │   ├── exfiltration.csv
  │   ├── fake_data_dev_with_exfiltration_on_c2server.csv
  │   ├── hijack.csv
  │   ├── link_pass_attack_with_pass.csv
  │   ├── log_collector.csv
  │   ├── log_wiper.csv
  │   ├── malware.csv
  │   ├── perm_tamper.csv
  │   ├── shadow_user.csv
  │   ├── ssh_keytampering.csv
  │   ├── SUID_privilege_escalation.csv
  │   ├── user_hunter.csv
  │   └── watcher.csv
  // One of the *rules*
  ├── sensitive_files.txt
  // Tracing program attached to the *LSM* hooks for socket interaction
  ├── socket
  │   ├── socket_ebpf.c
  │   ├── socket_ebpf.skel.h
  │   └── socket.h
  // Structs definitions, macros etc
  ├── utils
  │   └── utils.h
  // The vmlinux file
  └── vmlinux
      └── vmlinux.h
  ```

  #### 2. Types of programs
  - **_Tracing_**
    - These are the eBPF programs you can **ATTACH** on the **_system calls_**.
    - Let's take for example the attachment on the `sys_enter_execve` along with it's complement
      `sys_exit_execve`.

          ```c
              SEC("tracepoint/syscalls/sys_enter_execve")
              int trace_syscall_execve(struct trace_event_raw_sys_enter *ctx) {
                  /* rest of the code */
                  return 0;
              }
          ```

    - As you can see, we got a `MACRO` at teh very top of the our function, it is called `SEC`.
    - **SEC** comes from `section`. We tell the kernel where to attach our eBPF program. The kernel sees: **_"Oh, so you want to attach an eBPF program to the system call `sys_enter_execve`. Very well, if it passes the verifier, we good."_**
    - The `struct trace_event_raw_sys_enter *ctx` is how every `sys_enter_*` is defined in the kernel. It's the base struct definiton of the system call `enter`.
    - If you will run this, you will get the struct definition of the `sys_enter_execve` format:

      ```bash
      sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
      # you will get the struct definition of the sys_enter_execve format
      # On older kernels, it might be in /sys/kernel/debug/tracing/...
      name: sys_enter_execve
      ID: 782
      format:
          field:unsigned short common_type;	offset:0;	size:2;	signed:0;
          field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
          field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
          field:int common_pid;	offset:4;	size:4;	signed:1;

          field:int __syscall_nr;	offset:8;	size:4;	signed:1;
          field:const char * filename;	offset:16;	size:8;	signed:0;
          field:const char *const * argv;	offset:24;	size:8;	signed:0;
          field:const char *const * envp;	offset:32;	size:8;	signed:0;

      print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))

      ```

    - But if you want the `raw format` you can run this and get the result:

      ```bash
      sudo cat /sys/kernel/tracing/events/raw_syscalls/sys_enter/format

      # result

      name: sys_enter
      ID: 362
      format:
          field:unsigned short common_type;	offset:0;	size:2;	signed:0;
          field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
          field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
          field:int common_pid;	offset:4;	size:4;	signed:1;

          field:long id;	offset:8;	size:8;	signed:1;
          field:unsigned long args[6];	offset:16;	size:48;	signed:0;

      print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]
      ```

    - So based on what we see , if we access `ctx->args[0]` , we get the `filename`. If we access `ctx->args[1]` we will get the `argv` of the `execve` call and so on, just like I did here
      ```c
      const char *filename = (const char *)ctx->args[0];
      bpf_core_read_user_str(name, sizeof(name), filename);
      /* code omitted... */
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
      ```
    - So if you watch closely we used `bpf_core_read_user_str` and `#pragma unroll`. The `bpf_core_read_user_str`is a macro defined (verifier safe) that can safely read from the memory address into our buffer.
    - The eBPF verifier has to simulate every possible path our code could take. If we have a loop, the verifier gets stuck doing complex math to prove the loop will safely end across all those different paths, which causes it to hit its memory limit. `#pragma unroll` tells the compiler to just copy-paste the loop's contents into a straight line. The verifier loves straight lines, so it passes the code without complaining.
    - **_IMPORTANT NOTE : If our eBPF program passes 1 milion instruction, the verifier won't allow our program to be attached to the kernel._**
    - **The problem we are facing is `THE STATE EXPLOSION`**.
      - **Every time you write an `if/else statement`, the inspector (kernel verifier) splits into two timelines to check both possibilities.**

      - **If you have three if statements before your loop, the inspector is now tracking 8 different realities (2 x 2 x 2 = 8 paths).**

      - **The Loop Nightmare: When the verifier hits a loop, it has to simulate that loop over and over again for all 8 of those realities. If the loop runs 10 times, and has its own if statements inside it, the number of paths the inspector has to check multiplies exponentially.**

      - **Eventually, the verifier hits its maximum allowed instruction limit (often 1 million instructions) while trying to simulate all these branches, gives up, and rejects your program.**

    - **With the modern eBPF versions `5.3+` , we got support for bounded loops, but it requires writing the loop in a very specific way so the verifier can easily prove it stops. A little example:**

      ```c
      #define MAX_ITERATIONS 100 // Must be hard-coded constant

      SEC("tracepoint/syscalls/sys_enter_execve")
      int trace_execve(struct trace_event_raw_sys_enter *ctx) {
          int my_array[100] = {0}; // Let's say we do sometghin with this
          int total = 0;

          // NO #pragma unroll here!
          for (int i = 0; i < MAX_ITERATIONS; i++) {

              // The verifier accepts this because it can mathematically prove that 'i' will reach 100 and stop.

              total += my_array[i];
          }

          return 0;
      }
      ```

  - **_UPROBES_**
    - Ok, now moving on to the `UPROBES`. What are `UPROBES`?
    - **`BPF_PROG_TYPE_KPROBE` are eBPF programs that can attach to kprobes. KProbes are not a eBPF specific feature, but they do work very well together. Traditionally, one would have to write a custom kernel module which could be invoked from a kprobe or be content with just the trace log output. eBPF makes this process easier. (taken from [eBPF docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/))**
    - **Probes come in 5 different flavors: `kprobe`, `kretprobe`, `uprobe`, `uretprobe`, `usdt`. `kprobe and kretprobe` are used to probe the `kernel`, `uprobe and uretprobe` are used to probe `userspace`. The normal probes are invoked when the probed location is executed. The ret variants will execute once the function returns, allowing for the capture of the return value.**
    - For my use case , I needed `uprobe` and `uretprobe`. As the documentation said, you can attach them to the `userspace` (e.g A user enters his password when running a `sudo` command. .The `uprobe` catches this into `uretprobe`.)
    - Let's look at this example :

      ```c
      SEC("uprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_authenticate")
      int BPF_UPROBE(pam_authenticate_enter, pam_handle_t *pamh, int flags){
          /* rest of code */
          return 0;
      }
      ```

      - As you can see, I attached a `uprobe` on the `pam_authenticate` function. How did I find the `pam_authenticate` function ?
      - If we run :
        ```bash
        sudo nm -D /lib/x86_64-linux-gnu/libpam.so.0 | grep pam_auth
        # we will get this
        0000000000009b40 T pam_authenticate@@LIBPAM_1.0
        ```

        - The `nm` command **lists the "symbols" (functions and variables). Because it's a shared library, you need the -D flag to see the dynamic symbols.**
      - Ok, I see the function , I can attach a probe to it. But why did you use the parameters there. What is `pam_handle_t *pamh`,`int flags` ?
      - Every userspace function has it's own signature, parameters etc. So we need to look the definition of the functions from the userspace that we want to a attach a `uprobe` and give the same structure to our `uprobe`
      - So in our example for the `pam_authenticate` function we got our next definition (taken from the [linux docs for pam_auth](https://github.com/linux-pam/linux-pam/blob/master/libpam/pam_auth.c))

        ```c
                        /*
        * pam_auth.c -- PAM authentication
        *
        * $Id$
        *
        */

        #include "pam_private.h"
        #include "pam_prelude.h"

        #include <stdio.h>
        #include <stdlib.h>

        int pam_authenticate(pam_handle_t *pamh, int flags)
        {
            /* code omitted */
        }
        /* rest of code omitted */
        ```

      - We also need to define the `pam_handle_t` struct **EXACTLY IN THE ORDER** as it is on your system/docs, because otherwise **IT WILL READ GARBAGE**.
      - In `auth.h` you will find the definition :

        ```c
        typedef struct pam_handle_t{
            char *authtok;
            unsigned caller_is;
            void *pam_conversation;
            char *oldauthtok;
            char *prompt;
            char *service_name; // command
            char *user; // user who logs in
            char *rhost; // remote host/ip
            char *ruser; // remote user name
            char *tty; // terminal or pty from where the user logs in
            char *xdisplay;
            char *authtok_type;

        } pam_handle_t;
        ```

      - Also the definition from the [docs](https://github.com/linux-pam/linux-pam/blob/master/libpam/pam_private.h)

      ```c
      /* rest of code omitted */
      struct pam_handle {
          char *authtok;
          unsigned caller_is;
          struct pam_conv *pam_conversation;
          char *oldauthtok;
          char *prompt;                /* for use by pam_get_user() */
          char *service_name;
          char *user;
          char *rhost;
          char *ruser;
          char *tty;
          char *xdisplay;
          char *authtok_type;          /* PAM_AUTHTOK_TYPE */
          struct pam_data *data;
          struct pam_environ *env;      /* structure to maintain environment list */
          struct _pam_fail_delay fail_delay;   /* helper function for easy delays */
          struct pam_xauth_data xauth;        /* auth info for X display */
          struct service handlers;
          struct _pam_former_state former;  /* library state - support for
                          event driven applications */
          const char *mod_name;	/* Name of the module currently executed */
          int mod_argc;               /* Number of module arguments */
          char **mod_argv;            /* module arguments */
          int choice;			/* Which function we call from the module */

      #ifdef HAVE_LIBAUDIT
          int audit_state;             /* keep track of reported audit messages */
      #endif
          int authtok_verified;
          char *confdir;
      };
      /* rest of code omitted */
      ```

    - From here on, you can submit the data to a `buffer` and send the data to the `userspace`, or block a command also. Very flexible. In my case, it was purely for logging.

  #### 3. Program composition
  - To tell you about an eBPF program composition I need you to stick with me on some term definition. I know, it is very boring but we need it so that you will understand.
  - First we define the term **map**. A **map** is the bridge of communication between other **eBPF programs** or to the **userspace**. They are vital to our eBPF logging program.
  - **VERY IMPORTANT NOTE** about maps (taken directly from the [docs](https://docs.ebpf.io/linux/concepts/maps/)):
    > **When both kernel and user space access the same maps they will need a common understanding of the key and value structures in memory. This can work if both programs are written in C and they share a header. Otherwise, both the user space language and the kernel space structures must understand the k/v structures byte-for-byte.**
  - So having this is mind, it is very **important** in what we write the eBPF program and how we communicate on the other end with the userspace.
  - The program is composed of **3 main parts** :
    - #### 1. The headers
      ```c
      #include "../vmlinux/vmlinux.h"
      #include "socket.h"
      #include <bpf/bpf_helpers.h>
      #include <bpf/bpf_endian.h>
      #include <bpf/bpf_tracing.h>
      #include <bpf/bpf_core_read.h>
      ```
    - The base headers that every eBPF program would be are the `vmlinux.h`, `bpf/bpf_core_read.h`, `bpf/bpf_helpers.h` ,`bpf/bpf_tracing.h`. The `bpf/bpf_endian.h` is stuational (I needed it here because I had to convert some bytes from network to host order). In the base headers we find all the functions that we need to build a very structural eBPF program.

    - #### 2. Maps definitions
      - In this section we define the maps we use for the current eBPF program.
      - The powerfull capability is that they can be **shared** among the **eBPF programs** and the **userspace**. As we said earlier, they are the bridge of communication.
      - The maps are of more types, a lot of types actually which everyone is usefull in it's case.
      - Let's take a look into these definitions, you will understand more easily. These are all defined inside the `file_ebpf.c`.
        - The first one is called `blocked_filenames`. With the help of this map, we define one **rule** we mentioned earlier, e.g blocking some filenames we do not want to log. Maybe they are not important.
        - Like for example, take the command `cat /etc/shadow`. If we want to see all the files that are opened behind with this command, we can use:
          ```bash
          sudo strace -e trace=open,openat cat /etc/shadow
          # output below
          openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
          openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
          openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
          openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3
          ```
        - **So, of course, from here we would only the `openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3`, so other can be ignored since we are not interested in that level of sensitive logging. If a malicious script or malware is succesfully modyifing how the `cat` works behind, that we might be interested in that, but that is another discussion for another time.**
        - We added the **name** to the `blocked_filenames.txt` or the **pattern** in our case , because there is another `txt` called `blocked_patterns.txt` which blocks patterns, but is limited because of the kernel verifier. We'll get into further details later.
        - Here we used a map called `BPF_MAP_TYPE_HASH`. Very simple, as the name says, this is a **hash map**. Key-value pairs, very easy. Behind , for the implementation, they used a **hash table**.
        - **_VERY IMPORTANT NOTE (taken from the [docs](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/))_**
          > While the size of the key and value are essentially unrestricted, both value_size and key_size must be at least zero and their combined size no larger than KMALLOC_MAX_SIZE. KMALLOC_MAX_SIZE is the maximum size which can be allocated by the kernel memory allocator, its exact value being dependent on a number of factors. If this edge case is hit a -E2BIG error number is returned to the map create syscall.
        - We need to watch that values we define there, since we got some restrictions.

        ```c
        struct
        {
            __uint(type, BPF_MAP_TYPE_HASH);
            __uint(max_entries, 1024);
            __type(key, char[MAX_CHAR_LEN]);
            __type(value, __u8);
        } blocked_filenames SEC(".maps");
        ```

        - For the next map, we got a `BPF_MAP_TYPE_ARRAY`. How the name suggests, very simple , an **array** map. This is not essentially a map, but an array.
        - **_VERY IMPORTANT NOTE (taken from the [docs](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARRAY/))_**
          > While the value_size is essentially unrestricted, the key_size must always be 4 indicating the key is a 32-bit unsigned integer.
        - So , from the docs, the limit for keys is `__u32` , a 32 bit `unsigned int`.
          > The value of value_size shouldn't exceed KMALLOC_MAX_SIZE. KMALLOC_MAX_SIZE is the maximum size which can be allocated by the kernel memory allocator, its exact value being dependent on a number of factors. If this edge case is hit a -E2BIG error number is returned to the map create syscall.
        - On the other note, the `value_size` is essentialy unrestricted, but still we need to watch the numbers. Since we are on kernel level, we must be as cheap as possible.

        ```c
        struct
        {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, LITTLE_MAP_SIZE);
            __type(key, __u32);
            __type(value, char[MAX_PATTERN_LEN]);
        } blocked_patterns SEC(".maps");
        ```

        - And the final map, the `BPF_MAP_TYPE_RINGBUF`. By far the most important map, this was added on a newer version (`5.8`).
          This is essentially the map where we send all the logs. We defined a value of `8 Mb` for the buffer, but you can tweak t he value if you need more. . The value you put in the `max_entries` is essentially multiples of a page size (e.g `4096 * 32`, `4096 * 128`, etc). Why this is a smart choice ? Because of the implementation of the `ringbuf`
        - Since our eBPF logging is giving a lot of logs for output, it depends on the operation , up to `1000 logs/sec`, usual map operations are very slow here. Here the `BPF_MAP_TYPE_RINGBUF` comes into play.
        - First the userspace program (in our case `exec.c`) must **map** the **consumer** page
          ```c
          consumer = mmap(NULL, rb->page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
          ```

          - The consumer page is **writable**. While a whole page was mapped, only the first 8 bytes are used to represent a 64-bit unsigned integer, **the index of the consumer**.
        - The second area we need to **map** is the **producer** page.
          ```c
          mmap_sz = rb->page_size + 2 * (__u64)info.max_entries;
          producer = mmap(NULL, (size_t)mmap_sz, PROT_READ, MAP_SHARED, map_fd, rb->page_size);
          ```

          - The producer memory area is read-only. We map an area twice the size of the actual ring-buffer size plus 1 page, this is an optimization. The single, additional page is used to map the producer index, the same way we did for the consumer. The pages after that are the actual data. Since the buffer is a circular buffer, data can be split between the end of the buffer and the beginning. By mapping the physical memory twice into virtual memory we can read any overflowing data as if it was contiguous. ([eBPF ringbuff docs](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/))
        - So basically this is what happens:
          - **It is a shared block of memory: The Ring Buffer is an area of RAM that both the kernel and your user-space program are allowed to look at.**

          - **The Producer (Kernel): When your eBPF program catches an event (like a user typing a password in pam_authenticate), it asks the Ring Buffer for an empty slot. It writes the data into that slot, marks it as "ready," and immediately goes back to work. It never waits. This is tracked by a "Head" pointer.**

          - **The Consumer (User-space): Your user-space program constantly watches the conveyor belt. When it sees new data, it picks it up, processes it (like printing it to your screen), and marks that slot as "empty" so the kernel can use it again. This is tracked by a "Tail" pointer.**

        ```c
        struct
        {
            __uint(type, BPF_MAP_TYPE_RINGBUF);
            __uint(max_entries, 4096 * 512 * 32);
        } file_events SEC(".maps");
        ```

      - Let's also look a bit on this map from the `auth.c`
        ```c
        struct {
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
            __uint(max_entries, 1);
            __type(key, __u32);
            __type(value, TrackFileChanges);
        } scratchpad_map_pam_authenticate SEC(".maps");
        ```
      - This is a `BPF_MAP_TYPE_PERCPU_ARRAY`. Basically this is usefull because we can bypass two kernler verifier rules with this.
        - The first rule is that our eBPF programs have a restricted **stack size** of `512` bytes. So if we declare a `char arr[256]`, we just burnt `256` bytes.
        - Maps, on the other hand, do not live on the eBPF execution stack. When we create a **BPF_MAP_TYPE_PERCPU_ARRAY**, the memory is allocated dynamically in the kernel's heap during map creation. This allows you to define massive structs as the map's value
        - And the other rule is that , since this map is `PERCPU` , e.g the values are stored on different cpu's. Since we know that , there is no concurrency on that data, so safe read/writes.
      - **From docs**
        > According to the official kernel map_array.rst docs, the limit for a per-CPU array value is defined by the kernel's per-CPU allocator limit:
        > "The value stored can be of any size for BPF_MAP_TYPE_ARRAY and not more than PCPU_MIN_UNIT_SIZE (32 kB) for BPF_MAP_TYPE_PERCPU_ARRAY."
      - A little example would be this

        ```c
        // this is over the 512 byte limit
        struct massive_event {
            char filename[256];
            char username[256];
            char extra_data[1024];
        };

        //Per-CPu array with 1 slot
        struct {
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
            __type(key, u32);
            __type(value, struct massive_event);
            __uint(max_entries, 1);
        } scratchpad_map SEC(".maps");

        SEC("tracepoint/syscalls/sys_enter_execve")
        int trace_execve(struct trace_event_raw_sys_enter *ctx) {
            u32 index = 0;


            struct massive_event *event = bpf_map_lookup_elem(&scratchpad_map, &index);
            if (!event) return 0;


            bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ...);

            //  Submit it to a ring buffer, etc.

            return 0;
        }
        ```

      - So, **32 Kilobytes** is **massive** for eBPF and gives you plenty of room.

    - #### 3. Functions / Hooks definitions
      ```c
      SEC("lsm/socket_create")
      int BPF_PROG(socket_create, int protocol_family, int socket_type, int protocol, int kernel)
      {
          /* code omitted */
          return 0;
      }
      ```

      - Here we defined our signature function , as it is defined , in our case, into the **Linux Security Module**. In our case , it must **match** the definition.
    - Or we can have it attached to a system call :
      ```c
      SEC("tracepoint/syscalls/sys_enter_execve")
      int trace_syscall_execve(struct trace_event_raw_sys_enter *ctx) {
          /* code omitted */
          return 0;
      }
      ```

      - Here we only attach the program to the system call. Nothing complicated , the struct is already defined for us.
    - Or have it attached to a userspace function

      ```c
      SEC("uprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_authenticate")
      int BPF_UPROBE(pam_authenticate_enter, pam_handle_t *pamh, int flags){
          /* code omitted */
          return 0;
      }

      // with it's complement , the URETPROBE (the value returned, success of failure)

      SEC("uretprobe//usr/lib/x86_64-linux-gnu/libpam.so.0:pam_authenticate")
      int BPF_URETPROBE(pam_authenticate_exit, int ret){
          /* code omitted */
          return 0;
      }
      ```

      - Along the attachement via the `uprobe` , we need to define also the `uretprobe`, in which case we get the value returned, **success** or **failure**.
