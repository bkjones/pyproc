import os
import pwd
import socket
import struct

PROCDIR = '/proc'

def get_pids_by_uid(uid):
    pids = [x for x in os.listdir(PROCDIR) if x.isdigit() and \
            os.stat(os.path.join(PROCDIR, x)).st_uid == uid]

    return pids

def get_pids_by_uname(uname):
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

def get_open_files_by_pid(pid):
    pass
    


if __name__ == '__main__':
    assert ip_from_le_hex('881210AC') == '172.16.18.136'
