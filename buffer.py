"""
Experiment of ring buffer
"""

#!/usr/bin/python3  
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output); 
 
struct data_t {     
   int pid;
   int uid;
   int nano;
   char command[16];
};

int simple_output(void *ctx) {
   struct data_t data = {};

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.nano = bpf_ktime_get_ns();
   
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_get_current_comm(&data.nano, sizeof(data.nano));
 
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="simple_output")
 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.nano}")
 
print("tgid | gid | command executed | System boot elapsed")
b["output"].open_perf_buffer(print_event)

while True:   
   b.perf_buffer_poll()
