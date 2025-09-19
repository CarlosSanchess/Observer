#!/usr/bin/python3
from bcc import BPF
import argparse
import ctypes as ct
from parser import get_syscall_name,load_sys_table,is_in_table_name,get_syscall_id



def parse_args():
    parser = argparse.ArgumentParser(description="Provide a PID to trace all its system calls, or specify one to monitor.")
    
    parser.add_argument(
        '-p',"--pid", metavar='PID', type=int, nargs='*', 
        help="One to three PIDs to filter their syscalls. If no PID is provided, all syscalls will be shown.",
    )
    
    parser.add_argument(
        '-s', '--syscall', metavar='SYSCALL', type=str,
        help="One system call to filter. If no syscall is provided, all will be shown.",
    )
    
    args = parser.parse_args()

    if  args.pid and len(args.pid) > 1:
        print("You can provide up to 1 PIDs only.")
        exit(1)
    
    if args.syscall and len(args.syscall.split()) > 1: 
        print("You can provide up to 1 system call only.")
        exit(1)
    
    return args  

pid_filter = parse_args().pid 
sys_filter = parse_args().syscall  

prog = """

BPF_ARRAY(pids, u32, 1); /* PID's received from user input if any*/
BPF_ARRAY(syscall, u32, 1);
BPF_RINGBUF_OUTPUT(events, 2);

struct data_t {
    u32 pid;
    u32 sid;
};

int get_systemcall(void *ctx) {
    u32 *value;
    u32 key = 0;
    value = pids.lookup(&key);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 thisPid = pid_tgid >> 32;
    struct data_t data;
    u32 flag = -1;


    if (value) {
       if(thisPid == *value){
            data.sid = *value; // todo get the system call id in kernel space
            data.pid = *value;
            events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
        }
       if(*value == flag){
            data.sid = thisPid;
            data.pid = thisPid;
            events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
       }
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 key = 0;
    u32 flag = -1;

    u32* ret = syscall.lookup(&key); // we check if there is a single target
    
    if(ret){
        if(*ret == flag){
         return 0;
        }
    }
    u32* value = pids.lookup(&key);

    struct data_t data;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 thisPid = pid_tgid >> 32;

    if (value){ 
        if(thisPid == *value){
            u32 syscall_id = args->id;  
            data.sid = syscall_id;
            data.pid = *value;
            events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
        }
        if(*value == flag){
            u32 syscall_id = args->id; 
            data.sid = syscall_id;
            data.pid = thisPid;
            events.ringbuf_output(&data, sizeof(data), BPF_RB_FORCE_WAKEUP);
        }
    }
    

    
    return 0;
}


"""
file_path = '../data/sysTable.txt'  
sys_table = load_sys_table(file_path)
b = BPF(text=prog)

print("Tracing processes in the system... Ctrl-C to end")
print("%-8s %-8s %-20s" % ("PID", "SID", "COMM"))

pid_table = b.get_table("pids")

if pid_filter:
    pid_table[0] = ct.c_uint32(pid_filter[0])
else:
    pid_table[0] = ct.c_uint32(-1)

if sys_filter and is_in_table_name(sys_table, sys_filter):
    print("asdsa")
    syscall_table = b.get_table("syscall")     # there is a single syscall targeted, so we need to fill a map, so that the static tracepoint that gathers all sys calls doesnt exec normally
    syscall_table[0] = ct.c_uint32(-1)
    b.attach_kprobe(event=b.get_syscall_fnname(sys_filter), fn_name="get_systemcall") #attach dynamic kernel hook point


def print_event(cpu, data, size):
    """Callback function that will output the event data"""
   
    data = b["events"].event(data)  
 
    if sys_filter and len(sys_filter) > 0:
        print(("%-6s - %-6s - %-6s") % (data.pid, get_syscall_id(sys_table,sys_filter), sys_filter))
    else:
        print(("%-6s - %-6s - %-6s") % (data.pid, data.sid, get_syscall_name(sys_table, data.sid)))



b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit()