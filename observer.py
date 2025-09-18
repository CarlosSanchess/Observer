#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb
import argparse
import ctypes as ct

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
};

int hello_world(void *ctx) {
    bpf_trace_printk("Hello, world!\\n");
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
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

"""

b = BPF(text=prog)
#b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_world")

print("Tracing processes in the system... Ctrl-C to end")
print("%-6s %-6s %-20s %s" % ("PID", "UID", "COMM", "RUNTIME"))

if pid_filter:
    pid_table = b.get_table("pids")
    pid_table[0] = ct.c_uint32(pid_filter[0])

def print_event(cpu, data, size):
    """Callback function that will output the event data"""
    data = b["events"].event(data)  # BCC allows this simple map access from user spcae
    print("%-6s " % (data.pid))


b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit()