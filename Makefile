# execve_folder = execve_called
# file_open_folder = file_events
# process_events_folder = process_events
# socket_folder = socket
# auth_folder = auth_calls
# execve_called_ebpf = ebpf.c
# file_open_ebpf = file_ebpf.c
# process_events_ebpf = process_ebpf.c
# socket_ebpf = socket_ebpf.c
# auth_ebpf = auth.c

# all: run_exec

# file_open_called: $(file_open_folder)/$(file_open_ebpf) 
# 	cd $(file_open_folder) && \
# 	clang -O2 -g -target bpf -c $(file_open_ebpf) -o file_ebpf.o && \
# 	bpftool gen skeleton file_ebpf.o > file_open.skel.h

# execve_called: $(execve_folder)/$(execve_called_ebpf) file_open_called
# 	cd $(execve_folder) && \
# 	clang -O2 -g -target bpf -c $(execve_called_ebpf) -o ebpf.o && \
# 	bpftool gen skeleton ebpf.o > exec.skel.h

# process_exit_called: $(process_events_folder)/$(process_events_ebpf) execve_called
# 	cd $(process_events_folder) && \
# 	clang -O2 -g -target bpf -c $(process_events_ebpf) -o process_events_ebpf.o && \
# 	bpftool gen skeleton process_events_ebpf.o > process_exec.skel.h

# auth_called: $(auth_folder)/$(auth_ebpf) process_exit_called
# 	cd $(auth_folder) && \
# 	clang -O2 -g -target bpf -c $(auth_ebpf) -o auth_ebpf.o && \
# 	bpftool gen skeleton auth_ebpf.o > auth_ebpf.skel.h


# socket_called: $(socket_folder)/$(socket_ebpf) auth_called
# 	cd $(socket_folder) && \
# 	clang -O2 -g -target bpf -c $(socket_ebpf) -o socket_ebpf.o && \
# 	bpftool gen skeleton socket_ebpf.o > socket_ebpf.skel.h

# run_exec: socket_called
# 	gcc -g -o0 exec.c redis/redislogic.c -lelf -lbpf -lcjson -lhiredis -o exec.o
# 	LIBBPF_DEBUG=1 sudo ./exec.o

# # Clean everything
# clean:
# 	rm -f $(execve_folder)/ebpf.o $(execve_folder)/exec.skel.h
# 	rm -f $(file_open_folder)/file_ebpf.o $(file_open_folder)/file_open.skel.h
# 	rm -f $(socket_folder)/socket_ebpf.o $(socket_folder)/socket_ebpf.skel.h
# 	rm -f $(auth_called)/auth_ebpf.o $(auth_called)/auth_ebpf.skel.h
# 	rm -f $(process_events_folder)/process_events_ebpf.o $(process_events_folder)/process_exec.skel.h
# 	rm -f exec.o

# .PHONY: all execve_called file_open_called socket_called auth_called process_exit_called run_exec clean


execve_folder = execve_called
file_open_folder = file_events
process_events_folder = process_events
socket_folder = socket
auth_folder = auth_calls

execve_called_ebpf = ebpf.c
file_open_ebpf = file_ebpf.c
process_events_ebpf = process_ebpf.c
socket_ebpf = socket_ebpf.c
auth_ebpf = auth.c

# By default, just BUILD the program, don't run it yet.
all: build

file_open_called: $(file_open_folder)/$(file_open_ebpf) 
	cd $(file_open_folder) && \
	clang -O2 -g -target bpf -c $(file_open_ebpf) -o file_ebpf.o && \
	bpftool gen skeleton file_ebpf.o > file_open.skel.h

execve_called: $(execve_folder)/$(execve_called_ebpf) file_open_called
	cd $(execve_folder) && \
	clang -O2 -g -target bpf -c $(execve_called_ebpf) -o ebpf.o && \
	bpftool gen skeleton ebpf.o > exec.skel.h

process_exit_called: $(process_events_folder)/$(process_events_ebpf) execve_called
	cd $(process_events_folder) && \
	clang -O2 -g -target bpf -c $(process_events_ebpf) -o process_events_ebpf.o && \
	bpftool gen skeleton process_events_ebpf.o > process_exec.skel.h

auth_called: $(auth_folder)/$(auth_ebpf) process_exit_called
	cd $(auth_folder) && \
	clang -O2 -g -target bpf -c $(auth_ebpf) -o auth_ebpf.o && \
	bpftool gen skeleton auth_ebpf.o > auth_ebpf.skel.h

socket_called: $(socket_folder)/$(socket_ebpf) auth_called
	cd $(socket_folder) && \
	clang -O2 -g -target bpf -c $(socket_ebpf) -o socket_ebpf.o && \
	bpftool gen skeleton socket_ebpf.o > socket_ebpf.skel.h

# Just link and compile the final executable
build: socket_called
	gcc -g -O0 exec.c redis/redislogic.c -lelf -lbpf -lcjson -lhiredis -o ebpf_runner

# A dedicated run target if you want to test eBPF manually
run: build
	LIBBPF_DEBUG=1 sudo ./ebpf_runner

# Clean everything
clean:
	rm -f $(execve_folder)/ebpf.o $(execve_folder)/exec.skel.h
	rm -f $(file_open_folder)/file_ebpf.o $(file_open_folder)/file_open.skel.h
	rm -f $(socket_folder)/socket_ebpf.o $(socket_folder)/socket_ebpf.skel.h
	rm -f $(auth_folder)/auth_ebpf.o $(auth_folder)/auth_ebpf.skel.h
	rm -f $(process_events_folder)/process_events_ebpf.o $(process_events_folder)/process_exec.skel.h
	rm -f ebpf_runner

.PHONY: all build run file_open_called execve_called process_exit_called auth_called socket_called clean