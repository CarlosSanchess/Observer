#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb
import argparse
import ctypes as ct
from parser import get_syscall_name,load_sys_table




def parse_args():
    parser = argparse.ArgumentParser(description="Trace syscalls by PID")
    parser.add_argument(
        'pids', metavar='PID', type=int, nargs='*', 
        help="One to three PIDs to filter their syscalls. If no PID is provided, all syscalls will be shown.",
    )
    args = parser.parse_args()

    if len(args.pids) > 3:
        print("You can provide up to 3 PIDs only.")
        exit(1)
    
    return args.pids

pid_filter = parse_args()


# The eBPF program
prog = """

BPF_ARRAY(pids, u32, 3); /* PID's received from user input if any*/
BPF_RINGBUF_OUTPUT(events, 1);

struct data_t {
    u32 pid;
    u32 sid;
};

int get_systemcall_id(void *ctx) {
    u32 *value;
    u32 key = 0;
    value = pids.lookup(&key);
    if (value) {
        struct data_t data;
        data.pid = *value;


        events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
    }
    return 0;
}



TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 *value;
    u32 key = 0;
    value = pids.lookup(&key);
    if (value) {
        struct data_t data;
        data.pid = *value;
       // u64 pid_tgid = bpf_get_current_pid_tgid();
       // u32 thisPid = pid_tgid >> 32;
        u32 syscall_id = args->id;  // Assuming `args->id` contains the syscall ID
        data.sid = syscall_id;
        events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
    }
    return 0;
}


"""
file_path = 'sysTable.txt'  
sys_table = load_sys_table(file_path)
b = BPF(text=prog)
#b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_world")

print("Tracing processes in the system... Ctrl-C to end")
print("%-6s %-6s %-20s %s" % ("PID", "SID", "COMM", "RUNTIME"))

if pid_filter:
    pid_table = b.get_table("pids")
    pid_table[0] = ct.c_uint32(pid_filter[0])

def print_event(cpu, data, size):
    """Callback function that will output the event data"""
   
    data = b["events"].event(data)  
    print(("%-6s - %-6s - %-6s") % (data.pid, data.sid, get_syscall_name(sys_table, data.sid)))


b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit()