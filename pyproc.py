#!/usr/bin/env python

import os
import pwd
import socket
import struct
import errno
import glob
import sys
import collections
import resource

PROCDIR = '/proc'
PAGESIZE = resource.getpagesize()

__all__ = ['PMap', 'PStat', 'PStatM', 'Process', 'AddressRange', 'Device',
           'Limit', 'ip_from_le_hex', 'port_from_hex', 'port_status_from_hex']

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

def raw_read(file):
    '''
    Read a file in it's entirety and return the contents as a string.

    If the current user cannot access the file or the file doesn't exist,
    return None
    '''
    raw = None
    try:
        with open(file, 'r') as f:
            raw = f.read()
    except IOError as e:
        if e.errno not in (errno.EACCES, errno.ENOENT):
            raise(e)
    return raw


# Simple data structure that represents process maps (/proc/PID/map)
PMap = collections.namedtuple('PMap', ['addresses', 'perms', 'offset', 'dev',
                                       'inode', 'pathname'])

# Simple data structure that represents process stat (/proc/PID/stat)
PStat = collections.namedtuple('PStat', ['pid', 'comm', 'state', 'ppid',
                                         'pgrp', 'session', 'tty_nr',
                                         'tpgid', 'flags', 'minflt',
                                         'cminflt', 'majflt', 'cmajflt',
                                         'utime', 'stime', 'cutime',
                                         'cstime', 'priority', 'nice',
                                         'num_threads', 'itrealvalue',
                                         'starttime', 'vsize', 'rss',
                                         'rsslim', 'startcode', 'endcode',
                                         'startstack', 'kstkesp',
                                         'kstkeip', 'signal', 'blocked',
                                         'sigignore', 'sigcatch', 'wchan',
                                         'nswap', 'cnswap', 'exit_signal',
                                         'processor', 'rt_priority',
                                         'policy', 'delayacct_blkio_ticks',
                                         'guest_time', 'cguest_time'])

# Simple data structure that represents process statm (/proc/PID/statm)
PStatM = collections.namedtuple('PStatM', ['size', 'resident', 'share', 'text',
                                           'lib', 'data', 'UNUSED'])

# Simple data structure that represents address ranges. Used in PMap.
AddressRange = collections.namedtuple('AddressRange', ['start', 'end'])

# Simple data structure that represents devices (/dev/*) by major and minor numbers.
Device = collections.namedtuple('Device', ['major', 'minor'])

# Simple data structure that represents process limits.
Limit = collections.namedtuple('Limit', ['value', 'units'])

class Perms(object):
    '''
    Simple data structure representing permissions of mapped regions of a
    processes memory.
    '''
    def __init__(self, s):
        self.raw = s
        self.read = 'r' in s
        self.write = 'w' in s
        self.execute = 'x' in s
        self.shared = 's' in s
        self.private = 'p' in s

    def __repr__(self):
        return '<Perms %s>' % self.raw


class RODict(dict):
    '''
    Implement a Read Only Dictionary data structure that can
    be set, but not modified.

    It can only be set using keyword args on construction.
    e.g o = RODict(key1=val1, key2=val2, key3=val3)
    '''
    def __setitem__(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

    def clear(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

    def __delitem__(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

    def pop(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

    def popitem(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

    def update(self, *args):
        raise(TypeError("RODict is a read only dictionary"))

class Process(object):
    '''
    Represent a unix process.

    This makes heavy use of the data available within the proc(5) filesystem.
    Any data that a user has access to should be available. In general, this is
    kernel dependent, and was written against 2.6.38.

    Your mileage may vary. For more information, see proc(5).
    '''
    def __init__(self, pid):
        self.pid      = pid
        self.args     = self._args()
        self.environ  = self._environ()
        self.fds      = self._fds()
        self.limits   = self._limits()
        self.loginuid = self._loginuid()
        self.maps     = self._maps()
        self.root     = self._root()
        self.stat     = self._stat()
        self.statm    = self._statm()

    def __repr__(self):
        return "<Process pid:%d>" % self.pid

    def __str__(self):
        return ('%10d %8s %s' % (self.pid, self.loginuser, self.cmdline))

    @property
    def cmdline(self):
        '''
        Uses the current processes arguments to construct the commandline which
        generated this process.
        '''
        return ' '.join(self.args)

    @property
    def loginuser(self):
        '''
        Uses the current processes loginuid and the configured name service
        switch to determine the username of the user to whom this process
        belongs.
        '''
        try:
            pw = pwd.getpwuid(self.loginuid)
            return pw.pw_name
        except KeyError:
            return 'N/A'

    def _maps(self):
        '''
        Process /proc/PID/map and generate a list of the currently mapped memory
        regions for the process along with their access permissions.
        '''
        maps = list()
        raw = raw_read(self.pid_path('maps'))
        if raw is not None:
            for line in raw.split("\n"):
                if len(line) == 0:
                    continue
                if len(line) > 73:
                    path_part = len(line) - 73
                    format = '@73s%ds' % path_part
                    raw_fields, raw_pathname = struct.unpack(format, line)
                    fields   = raw_fields.split()
                    addresses  = [int(v, 16) for v in fields[0].split('-')]
                    range    = AddressRange(*addresses)
                    perms    = Perms(fields[1])
                    offset   = int(fields[2], 16)
                    dev      = [int(v, 16) for v in fields[3].split(':')]
                    device   = Device(*dev)
                    inode    = int(fields[4])
                    pathname = raw_pathname.strip()
                    maps.append(PMap(range, perms, offset, device, inode,
                                     pathname))
                else:
                    fields   = line.split()
                    addresses  = [int(v, 16) for v in fields[0].split('-')]
                    range    = AddressRange(*addresses)
                    perms    = Perms(fields[1])
                    offset   = int(fields[2], 16)
                    dev      = [int(v, 16) for v in fields[3].split(':')]
                    device   = Device(*dev)
                    inode    = int(fields[4])
                    pathname = None
                    maps.append(PMap(range, perms, offset, device, inode,
                                     pathname))
            return maps
        else:
            return None

    def _root(self):
        '''
        Read the link /proc/PID/root to determine the root of the filesystem as
        per this process. Will normally be / unless set by the use of the
        chroot(2) system call.
        '''
        try:
            root = os.readlink(self.pid_path('root'))
        except OSError as e:
            if e.errno == errno.EACCES:
                return None
            elif e.errno == errno.ENOENT:
                return None
            else:
                raise(e)
        return root

    def pid_path(self, *args):
        '''
        Helper routing which can be used to concatenate paths relative to this
        processes directory in the proc filesystem.
        '''
        parts = [PROCDIR, str(self.pid)]
        for arg in args:
            parts.append(str(arg))
        return(os.path.join(*parts))

    def _fds(self):
        '''
        Process the contents of /proc/PID/fd to get a read only dictionary
        indexed by file descriptor number including all of the processes open
        files. These can include any kind of valid unix file, so it is not safe
        to assume this will only include paths to regular files.
        '''
        fds = dict()
        try:
            for fd in os.listdir(self.pid_path('fd')):
                fds[fd] = os.readlink(self.pid_path('fd', fd))
        except OSError as e:
            if e.errno == errno.EACCES:
                return None
            elif e.errno == errno.ENOENT:
                return None
            else:
                raise(e)
        return RODict(fds)

    def _loginuid(self):
        '''
        Process the contents of /proc/PID/loginuid to determine the uid of the
        process which owns the given process.
        '''
        uid = raw_read(self.pid_path('loginuid'))
        if uid is not None:
            return int(uid)
        else:
            return None

    def _args(self):
        '''
        Process the contents of /proc/PID/cmdline to determine a list of
        arguments necessary to reconstruct the commandline of the given process.
        '''
        raw = raw_read(self.pid_path('cmdline'))
        if raw is not None:
            return raw.split('\0')[0:-1]
        else:
            return None

    def _environ(self):
        '''
        Process the contents of /proc/PID/environ to determine the working
        environment in which the given process is running. Returns a read only
        dictionary which includes all of the environment's variables.
        '''
        raw = raw_read(self.pid_path('environ'))
        if raw is not None:
            environ = dict()
            for data in raw.split('\0')[0:-1]:
                try:
                    key, val = data.split('=', 1)
                except ValueError:
                    key = data.rstrip('=')
                    val = None
                environ[key] = val
            return RODict(environ)
        else:
            return None

    def _limits(self):
        '''
        Processes the contents of /proc/PID/limits to generate a read only
        dictionary including the hard and soft process limits for the given
        process.

        For more information see getrlimit(2)
        '''
        raw = raw_read(self.pid_path('limits'))
        if raw is not None:
            def convert(s):
                s = s.strip()
                try:
                    s = int(s)
                except ValueError:
                    pass
                return(s)
            limits = {}
            for line in raw.split("\n"):
                if line.startswith('Limit'):
                    continue
                if line == '':
                    continue
                try:
                    data = [convert(v) for v in struct.unpack('@26s21s21s10s',
                                                              line)]
                    ltype = data[0]
                    lsoft = data[1]
                    lhard = data[2]
                    lunit = data[3]
                    limits[ltype] = {
                        'soft': Limit(lsoft, lunit),
                        'hard': Limit(lhard, lunit)
                        }
                except struct.error:
                    data = [convert(v) for v in struct.unpack('@26s21s21s',
                                                              line)]
                    ltype = data[0]
                    lsoft = data[1]
                    lhard = data[2]
                    lunit = 'N/A'
                    limits[ltype] = {
                        'soft': Limit(lsoft, lunit),
                        'hard': Limit(lhard, lunit)
                        }
            return RODict(limits)
        else:
            return None

    def _stat(self):
        '''
        Process the contents of /proc/PID/stat to determine the status
        information about the given process. This is used exhaustively by the
        ps(1) command. All values which are associated with memory usage are
        measured in bytes.

        Returns a PStat data structure.
        '''
        raw = raw_read(self.pid_path('stat'))
        if raw is not None:
            def convert(s):
                s = s.strip()
                try:
                    s = int(s)
                except ValueError:
                    pass
                return(s)
            data = [convert(v) for v in raw.split()]
            for index in [23, 35, 36]:
                data[index] = data[index] * PAGESIZE
            stat = PStat(*data)
            return stat
        else:
            return None

    def _statm(self):
        '''
        Processes the contents of /proc/PID/statm to determine information about
        the processes usage of memory. While the /proc/PID/statm file measures
        memory usage in pages, this represents memory usage in bytes.

        Returns a PStatM data structure.
        '''
        raw = raw_read(self.pid_path('statm'))
        if raw is not None:
            data = [ int(v) * PAGESIZE for v in raw.split()]
            statm = PStatM(*data)
            return(statm)
        else:
            return None

    @classmethod
    def list(cls, uid=None, username=None):
        '''
        Class method which can be used to lookup all processes, or processes
        filtered by username or uid.
        '''
        if username is not None:
            try:
                uid = pwd.getpwnam(username).pw_uid
            except KeyError:
                uid = False
        processes = []
        for dir in os.listdir(PROCDIR):
            if dir.isdigit():
                if uid is not None:
                    if os.stat(os.path.join(PROCDIR, dir)).st_uid == uid:
                        processes.append(Process(int(dir)))
                else:
                    processes.append(Process(int(dir)))
        return processes


if __name__ == '__main__':
    import pprint
    def report(p):
        print repr(p)
        print p
        print p.loginuser
        print p.root
        pprint.pprint(p.fds)
        pprint.pprint(p.limits)
        pprint.pprint(p.maps)
        pprint.pprint(p.statm)
        pprint.pprint(p.stat)
    for p in Process.list(uid=500):
        report(p)

