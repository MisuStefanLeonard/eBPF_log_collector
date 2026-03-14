# STEPS

## 1. eBPF installation

( if you want to see the .elf or dissasembly with bpftool and to set permissions on  eBPF programs e.g only ADMIN capabilities or ROOT, run this, ((--HERE it is not needed--)) , than continue with the rest)

```bash
sudo apt-get update
sudo apt install git build-essential clang llvm libbpf-dev libssl-dev
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

### Ubuntu > 22.04
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


