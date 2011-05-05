import os
import pwd
import socket
import struct

PROCDIR = '/proc'

def get_pids_by_uid(uid):
    """
    Builds a list of pids belonging to uname by inspecting the 
    owner of the pid directories under /proc.

    """
    pids = [x for x in os.listdir(PROCDIR) if x.isdigit() and \
            os.stat(os.path.join(PROCDIR, x)).st_uid == uid]

    return pids

def get_pids_by_uname(uname):
    """
    Builds a list of pids belonging to uname by inspecting the 
    owner of the pid directories under /proc.

    """
    pids = [x for x in os.listdir(PROCDIR) if x.isdigit() and \
            pwd.getpwuid(os.stat(os.path.join(PROCDIR, x)).st_uid).pw_name == uname]

    return pids

def ip_from_le_hex(le_hex):
    """
    le_hex is a little-endian hex representation of an IP address, 
	a format used by the C library and found in (for our case) 
	/proc/net/tcp. This returns a dotted-quad IP address. 

    """
    laddr = int(le_hex, 16)
    packed_ip = struct.pack("<L", laddr)
    ip = socket.inet_ntoa(packed_ip)
    return ip

def port_from_hex(p_hex):
    """
    Return the integer port number given a 
    hex representation. 

    """
    return int(p_hex, 16)

def port_status_from_hex(hex_status):
    """
    Mapping ripped straight from tcp_states.h 
    file in the Linux kernel source (last updated 
    for the ubuntu-distributed '2.6.38-8' kernel

    """
    hexmap = {1: 'ESTABLISHED',
              2: 'TCP_SYN_SENT',
              3: 'TCP_SYN_RECV',
              4: 'TCP_FIN_WAIT1',
              5: 'TCP_FIN_WAIT2',
              6: 'TCP_TIME_WAIT',
              7: 'TCP_CLOSE',
              8: 'TCP_CLOSE_WAIT',
              9: 'TCP_LAST_ACK',
              10: 'TCP_LISTEN',
              11: 'TCP_CLOSING',
              12: 'TCP_MAX_STATES'}

     return hexmap(int(hex_status, 16))

def get_open_files_by_pid(pid):
    pass
    


if __name__ == '__main__':
    assert ip_from_le_hex('881210AC') == '172.16.18.136'
