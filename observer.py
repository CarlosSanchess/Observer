#!/usr/bin/python3
from bcc import BPF
from bcc.utils import printb
import argparse

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

struct data_t {
    u64 pid;
};

int hello_world(void *ctx) {
    bpf_trace_printk("Hello, world!\\n");
    return 0;
}

"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_world")

print("Tracing processes in the system... Ctrl-C to end")
print("%-6s %-6s %-20s %s" % ("PID", "UID", "COMM", "RUNTIME"))

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))