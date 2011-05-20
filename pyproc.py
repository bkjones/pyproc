import os
import pwd

PROCDIR = '/proc'

def get_pids_by_uid(uid):
    pids = [x for x in os.listdir(PROCDIR) if x.isdigit() and \
            os.stat(os.path.join(PROCDIR, x)).st_uid == uid]

    return pids

def get_pids_by_uname(uname):
    pids = [x for x in os.listdir(PROCDIR) if x.isdigit() and \
            pwd.getpwuid(os.stat(os.path.join(PROCDIR, x)).st_uid).pw_name == uname]

    return pids

def get_open_files_by_pid(pid):
    


if __name__ == '__main__':
    puid = get_pids_by_uid(1000)
    pname = get_pids_by_uname('jonesy')
    print "By UID: %s" % puid
    print "By Name: %s" % pname
