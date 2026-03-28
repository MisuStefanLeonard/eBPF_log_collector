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
sudo -i  # ( change to root )

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

  - #### 4. Programs entrypoint
    - Now we will talk about the bridge between all the **eBPF programs**. How we connect them and how we manipulate the data that we receive through the **ringbuffer** map.
    - First off, I will need to introduce you to a new term, called **skeleton**.
    - Every **eBPF program** has a skeleton. In that skeleton we got the main functions to load and mount our eBPF programs. Let's look at this piece of code :
      ```c
      struct file_ebpf *file_skel = file_ebpf__open();
      if (!file_skel)
      {
          fprintf(stderr, "Failed to open file events skeleton\n");
          return 1;
      }
      ```

      - The function `file_ebpf__open()` initializes our eBPF skeleton and from that on we can load our program into the **userspace**
      - Then we load the skeleton we just initialized :
        ```c
        if (file_ebpf__load(file_skel)) {
          fprintf(stderr, "Failed to load file_ebpf skeleton\n");
          goto cleanup;
        }
        ```
      - Then we need to attach the skeletons to our main program execution
        ```c
        if (file_ebpf__attach(file_skel))
        {
            fprintf(stderr, "Failed to attach file events skeleton\n");
            goto cleanup;
        }
        ```
      - These are all the steps required to load an eBPF program into the userspace.
    - In concordance with the program entrypoint we got to talk about some serious notes.
    - First let's look at a few definitions of the **maps**. This is **_FIRST DFINED_** into the `file_ebpf.c`. Please take into account **FIRST DEFINED**.
      ```c
      struct
      {
          __uint(type, BPF_MAP_TYPE_RINGBUF);
          __uint(max_entries, 4096 * 512 * 32);
      } file_events SEC(".maps");
      ```
    - Then as we can see , we got another definition into our `ebpf.c`:
      ```c
      struct {
          __uint(type, BPF_MAP_TYPE_RINGBUF);
          __uint(max_entries, 4096 * 512 * 32); // 8mb
      } file_events SEC(".maps");
      ```
    - _So , very important , if we plan to use the **same map** into multiple eBPF programs, we must define the respective **map** in every eBPF program._
    - So, if we come back to what we talked about earlier about how we _**create, load and attach**_ an eBPF program, the **first eBPF program** that should take this steps is the **main eBPF program**, which in our case is the `file_ebpf.c` so of course , we load and attach every other **eBPF program** after we _**create, load and attach**_ the eBPF program. So for example :
      - We first created the `struct file_ebpf *file_skel` and all the others skeletons after :

      ```c
      // BUT VERY IMPORTANT, THE MAIN SKELETON MUST BE LOADED FIRST!
      struct file_ebpf *file_skel = file_ebpf__open();
      if (!file_skel)
      {
          fprintf(stderr, "Failed to open file events skeleton\n");
          return 1;
      }
      // than we loaded all the other programs

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
      ```

      - After that, we **load** only the **main** skeleton.
        ```c
        if (file_ebpf__load(file_skel)) {
          fprintf(stderr, "Failed to load file_ebpf skeleton\n");
          goto cleanup;
        }
        ```
      - Than, into the next 20 lines of code, we introduce a new term called **map pinning**. The definition of **map pinning** is that if we want a map to persist, even after our eBPF programs are done finishing and we exit, they still **remain pinned** into our system, which is a _**very powerfull**_ tool. Why?
      - Take the scenario that I got hit by. When i send the data to the **redis stream** and my **python program** receives the data also from **redis**, these things gets logged and they are _**very noisy**_. So we kinda want to block the **_python PID_** , but only after the **eBPF program** started. So we pin the map which it's called in our case `self_pid` to the system, than we inject manually the **python pid** into the map via the command `bpftool map update pinned`.
      - **The default path for the **map pinning** is at `/sys/fs/bpf/<map_name>`**
      - Also, I added a bool variable to check if the map is already **pinned** or **not** for safety checks and to avoid errors.
      - This is the code :

        ```c
        /* IMPORTANT FOR THE PYTHON PART*/
        fprintf(stdout, "Pinning map (self_pid) to /sys/fs/bpf/self_pid_map\n");
        bool skipPinning = false;
        bool isMapPinnedAlready = bpf_map__is_pinned(file_skel->maps.self_pid);
        if (isMapPinnedAlready == true){
            fprintf(stdout, "Map is already pinned... Continue...\n");
            skipPinning = true;
        }

        if (skipPinning != true){
            unsigned int isPinned = bpf_map__pin(file_skel->maps.self_pid, "/sys/fs/bpf/self_pid_map");
            if (isPinned == 0){
                fprintf(stdout, "(SUCCESS) Succesfully pinned map (self_pid) to /sys/fs/bpf/self_pid_map\n");

            }else{
                fprintf(stderr, "(FAIL) Unsuccesfully pinned map (self_pid) to /sys/fs/bpf/self_pid_map\n");
                goto cleanup;
            }
        }else{
            fprintf(stdout,"Skipped map pinning....\n");
        }
        ```

      - In the next step, we retrieve the **file descriptors** for every map we defined , to reuse the maps across all eBPF programs.
        ```c
        int ring_buffer_fd        = bpf_map__fd(file_skel->maps.file_events);
        int blocked_patterns_fd   = bpf_map__fd(file_skel->maps.blocked_patterns);
        int self_pid_fd           = bpf_map__fd(file_skel->maps.self_pid);
        int comm_filtering_fd     = bpf_map__fd(file_skel->maps.comm_filtering);
        int active_file_pids_fd   = bpf_map__fd(file_skel->maps.active_file_pids);
        int blocked_patterns_pids_fd = bpf_map__fd(file_skel->maps.blocked_patterns_pids);
        int blocked_filenames_fd = bpf_map__fd(file_skel->maps.blocked_filenames);
        ```
      - We now reuse the maps in every skeleton from every eBPF program

        ```c
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
        ```

      - And after we just **created and loaded** all the skeletons and the main skeleton is **created, and loaded**, only after that we load all the other skeletons:

        ```c
        /*
        ───────────────────────────────────────────────
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

        ```

      - You may ask yourselves now. Why we first needed to load the main skeleton than the others?
      - Because we had to **reuse** the maps across all the other eBPF programs, so they had to be **_mounted_** first. We then retrieved their **file descriptors** to reuse them across all the other eBPF programs with `bpf_map__reuse_fd`.

    - In the next pieces of code, we come across on the **stiff rules** we talked about earlier. They will block us either **pids** we do not want to log, or **filenames** we do not want , or **command names** and so on.
      ```c
      load_into_maps(file_skel,"blocked_filenames.txt",1024,MAX_CHAR_LEN, sizeof(__u8), 'f' , "blocked_filenames", 0);
      // load file_skel - blocked_comm_names
      load_into_maps(file_skel,"blocked_comm_names.txt",128,TYPE, sizeof(__u8), 'f' , "comm_filtering", 0);
      // load into execve_skell - blocked_coms_from_filames
      load_into_maps(execve_skel,"blocked_comm_names_from_filenames.txt",256,TYPE_3, sizeof(__u8), 'e' , "blocked_comms_from_filenames", 0);
      // load file_skel - blocked_patterns
      load_into_maps(file_skel, "blocked_patterns.txt", LITTLE_MAP_SIZE, sizeof(uint32_t), MAX_PATTERN_LEN, 'f', "blocked_patterns", 1);
      // load socket_skel - blocked_comm
      load_into_maps(socket_skel, "blocked_comm_names_sockets.txt", 128, TYPE, sizeof(__u8), 's', "socket_comm_filtering", 0);
      ```
    - Then for the final step we attach all the eBPF programs, with of course the first one being the `file_ebpf` skeleton. After that we connect to the **redis stream** on **localhost**. After the connection has been established, we **pool** the **ringbuffer** to receive the data that has been written from the kernel side of eBPF programs.
    - In the `cleanup` section, in case of **stopping** or **failure** we clean the traces of the program for a new start again.

      ```c

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
        file_events = ring_buffer__new(ring_buffer_fd,handle_event, NULL, NULL);

        int pid = getpid();
        printf("Current PID: %d\n", pid);
        sleep(1);

        __u32 key = 0;
        if (bpf_map__update_elem(file_skel->maps.self_pid, &key, sizeof(key), &pid, sizeof(pid), BPF_ANY) < 0)
        {
            perror("bpf_map_update_elem failed");
            goto cleanup;
        }

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        while (!isStopped)
        {
            int err = ring_buffer__poll(file_events, 100);


            if (err == -EINTR) {
                break;
            }

            // Catch any other actual errors
            if (err < 0) {
                printf("Error polling ring buffer: %d\n", err);
                break;
            }
        }

      cleanup:
          if (csv_file)
              fclose(csv_file);

          if (file_events)
              ring_buffer__free(file_events);

          if (client)
              redisFree(client);

          bpf_map__unpin(file_skel->maps.self_pid, "/sys/fs/bpf/self_pid_map");
          file_ebpf__destroy(file_skel);
          ebpf__destroy(execve_skel);
          process_events_ebpf__destroy(proc_skel);
          auth_ebpf__destroy(auth_skel);
          socket_ebpf__destroy(socket_skel);


          return 0;
      ```

    - #### 5. Log structure
      - Ok, we've talked enough about the eBPF program structure, about the entrypoints and how we can connected them together. Now let's see a bit about the structure of the logs we collect.
      - The events we tracked are the following:
        ```c
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
          } event_type;
        ```
      - From what you can see we track **file tampering**. Whether is a `chmod`, `rmdir` , `rm`, a `ln`, etc. , we track everything. So every move of every script,command, etc gets **logged**.
      - We also track **user interaction**. From **passwd changes**, to **user changes**, to any **sudo** interaction to everything related to the **user**.
      - And I choose here lastly the most important **socket interactions**. From what you can see I included the cycle of the socket : `Creation -> Binding -> Listening -> Connecting -> Accepting`.
      - Now moving on next our main struct called `TrackFileChanges` is composed of little structures, every one of them from it's very importance, which I will start to describe now.
      - We have the `Generics` struct. Here we define the general things that should appear in **every log**. From **_pid,ppid,uid,gid_** to **_exit_code,argv,filename and command name_**. For the **argv** part , I defined the macros `MAX_ARGS_CAPTURED` which is the value of `12` with `MAX_ARGV_LEN` of `64`.
        ```c
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
        ```
      - We have the `AuthEvent` struct. In here we track everything related to the **authentication** events. As you can observe, a **padding** has been added for `8-byte allignment`.
        ```c
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
        ```
      - We move now to the `SocketEvent`. Here we track eveything related to the **socket interaction**. **Padding** has been also added here for `8-byte allignment`.
        ```c
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
        ```
      - We can now compose the main struct `TrackFileChanges` where we added a few more **important** attributes

        ```c
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
        ```

      - What I added new here:
        - **Time tampering attributes :**
          ```c
          unsigned long long old_mtime; // 8
          unsigned long long new_mtime; // 8
          unsigned long long old_ctime; // 8
          unsigned long long new_ctime; // 8
          unsigned long long old_atime; // 8
          unsigned long long new_atime; // 8
          ```
        - **File related attributes:**
          - The `fptr` , `has_emitted_read` , `has_emitted_write` have been used to check whether on a file a **read** or **write** operation has been made, alongside the `inode_number` and `inode_number_new` to find the **file** that someone **tried** to modify.

            ```c
            unsigned long fptr;
            int has_emitted_read;
            int has_emitted_write;

            unsigned long inode_number; // 8
            unsigned long inode_number_new; // 8
            ```

        - **File metadata attributes**
          - `mode` and `new_mode` are the `file permission bits`. We read them in `octal (base 8)` and converted them into `base 10`. Maximum value of the permission bits in linux can be `7777`. Also we tracked if the `owner` of the **file** has been changed, even if it's the `group` or `user`.
          ```c
          unsigned int mode; // 4
          unsigned int new_mode; // 4
          unsigned int old_uid; // 4
          unsigned int new_uid; // 4
          unsigned int old_gid; // 4
          unsigned int new_gid; // 4
          ```
        - **Device numbers**
          - In case of tampering with the `/dev/`, we also tracked some data about the device numbers, but also used them to retrieve the `full path` of the **file**. Why you may ask yourselves ? I will respond to your question in the next few chapters, but for now, trust me, we needed them.
          ```c
          // Device numbers
          unsigned int dev_major; // 4
          unsigned int dev_minor; // 4
          unsigned int dev_major_new; // 4
          unsigned int dev_minor_new; // 4
          unsigned int rdev_major; // 4
          unsigned int rdev_minor; // 4
          unsigned int rdev_major_new; // 4
          unsigned int rdev_minor_new; // 4
          ```
        - **Permission / Commands tampering**
          - We added more attributes here in case of the **tampering** with the files. A `sgid` bit has been set , whether the targeted `dir` is `world_writable` (from the `ln` command) etc.
          - We also tracked here the `file_type , file_type_new` and the `new_filename` name. Maybe an attacker tries to hide something under `.log` extension or `.tmp`.

          ```c
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
          ```

      - All these fields gave me the possibility to make a pretty accuarate prediction algorithm and in **real-time** also. I did not use these fields exactly, but they were the base to the **vector** I feed to the ML algorithm.
      - Now, we are done with the struct definition. Now another problem must be face. We first need to define the problem.
      - **_Kernel verifier does not permit the infinite `recursion`_**.
        - So after we all know the definition of the files into our linux system is in a `tree` way. So to get the full path of a file , we need to **recursively** traverse the **tree** until the **root**.
        - We have `example.txt` defined in the next structure :
          ```bash
          /
          |
          home
            |
            |__ stefan
                  |
                  |_ myDir
                  |_ myDir2
                        |
                        |_ example.txt
          ```
        - To get the full path, we need to `recursively` traverse the _parent_ beggining from the **leaf** (`example.txt`) because of how the linux structures `pathing`. So we would need to go `example.txt -> myDir2 -> stefan -> home -> /`. Observe that we need to stop at `/`.
        - So from the linux docs, we can get all the structures we need
          - `struct dentry` **(The "Link" in the Chain)**

          ```c
            struct dentry {
              /* rest of members omitted */
              struct inode             *d_inode;     /* associated inode */
              // this is the parent of the current file we are in
              struct dentry            *d_parent;    /* dentry object of parent */
              // this is real name of our current file
              struct qstr              d_name;       /* dentry name */
              /* rest of members omitted */

          };
          ```

          - `struct vfsmount` **(The Anchor)**
            - A path is not just a name. The system needs to know where has been **mounted**. If you have a separate drive from `/home` , the system need to know the **mount point**
          - `struct path` \*\*(The bridge)
            - This struct combines both `struct vfsmount` and `struct dentry` into one single struct called `path`
              ```c
              struct path {
                  struct vfsmount *mnt;
                  struct dentry *dentry;
              };
              ```
          - So with the help of these we can get the full path of a file. But this works very well in plain C code right? On the kernel , because the verifier will not allow this **recursion** we cannot do that, or we can do it until a point. But what if the depth of our tre is bigger than 4 ? Or bigger than 20 ?

        - How to solve this ? Well instead of getting the full path in kernel (which would have been faster) , we get it from the **userspace**. How ?
        - Using the **mount point** of where the file is mounted, than recursively searching into the tree until we find the `/`. But with a few safety checks. If two files with the same name are mounted on different `devs` ? Than we need to safely recurse so that we will not enter **the other dev**

        ```c
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
        ```

      - And now we resolved the problem with the **full path**.
      - Complementary, we get the full path of the executable also :

        ```c
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
        ```
  - #### 6. Macro definitions
    - I defined some constants to use across the program
    - They are either use for **file permissions** or to extract **socket data**, either constants to use for defining different sizes.
      - One interesting constant that is there is the `MAX_ITERS_FOR_STRSTR` which seems like a **magic number**, `128`. Well, it is not a magic number if you ask yourself , it is the max limit for the `strstr(needle, haystack)` I implemented on **kernel level**. It is the maximum size for the **needle** , e.g the maximum length of the pattern that it can search in a **string**. 
      - If we try to increment this , the **verifier** tells us that there are too much **instructions** generated into the verifier tree.
      - This is the implementation for the `strstr()` function.
        ```c
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
        ```
      ```c
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
      #define ATTR_MODE	1
      #define ATTR_UID	2
      #define ATTR_GID	4
      #define ATTR_ATIME	16
      #define ATTR_MTIME	32
      #define ATTR_CTIME	64
      // family types
      #define AF_UNIX		1	/* Unix domain sockets 		*/
      #define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
      #define AF_INET		2	/* Internet IP Protocol 	*/
      #define AF_INET6	10	/* IP version 6			*/
      #define AF_PACKET	17	/* Packet family		*/

      // Permission bits mask
      #define MODE_MASK 07777

      ```
  - #### 7. How the verifier works / Problems
    - How the eBPF verifier works ?
      > **The safety of the eBPF program is determined in two steps.**
      > **First step does DAG check to disallow loops and other CFG validation. In particular it will detect programs that have unreachable instructions. (though classic BPF checker allows them)**
      > **Second step starts from the first insn and descends all possible paths. It simulates execution of every insn and observes the state change of registers and stack.**
      > At the start of the program the register R1 contains a pointer to context and has type _**PTR_TO_CTX**_. If verifier sees an insn that does _**R2=R1**_, then **R2** has now type _**PTR_TO_CTX**_ as well and can be used on the right hand side of expression. If _**R1=PTR_TO_CTX**_ and insn is _**R2=R1+R1**_, then _**R2=SCALAR_VALUE**_, **since addition of two valid pointers makes invalid pointer.**
      > **In ‘secure’ mode verifier will reject any type of pointer arithmetic to make sure that kernel addresses don’t leak to unprivileged users**
    - More information about the different errors that can appear, check the [eBPF documentation](https://docs.kernel.org/bpf/verifier.html).
    - To add more here...


