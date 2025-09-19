def load_sys_table(file_path):
    """
    Load the SysTable file and return a dictionary of syscall_id -> syscall_name.
    Assumes file format: `id,name`
    """
    sys_table = {}
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(',')
            sys_table[int(parts[0])] = parts[1]
    
    return sys_table

def get_syscall_name(sys_table, syscall_id):
    """
    Given a syscall ID, return the corresponding syscall name.
    """
    return sys_table.get(syscall_id, "Unknown ID")

def is_in_table_name(sys_table, syscall_name):
    """
    Check if a syscall name exists in the syscall table.
    """
    return syscall_name in sys_table.values()

def get_syscall_id(sys_table, syscall_name):
    """
    Given a syscall name, return the corresponding syscall ID.
    """
    for syscall_id, name in sys_table.items():
        if name == syscall_name:
            return syscall_id
    return -1  
    