import time
import sys
import getopt
import os
import json
import re
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt


class PreLog:

    def __init__(self, path, pids):
        self.path = path
        self.pids = pids

    def hook_pre(self):
        pid_re = re.compile(r'\[[1-9]\d*\]')
        self.pids = list()
        files = os.listdir(os.getcwd())
        for i in files:
            if "strace" in i:
                self.pids.append(i.split(".")[1])
        with open("hook.log", 'r') as hook_file:
            with open("hook_new.log", 'w') as hook_new:
                for line in hook_file:
                    pid_obj = pid_re.search(line).group()
                    if pid_obj:
                        if re.findall(r'\d+', pid_obj)[0] not in self.pids:
                            pass
                        else:
                            hook_new.write(line)

    def add_pid(self):
        files = os.listdir(os.getcwd())
        pid = str()
        with open('merge.log', 'a') as merge_log:
            for i in files:
                if "strace" in i:
                    pid = i.split(".")[1]
                    with open(i, 'r') as strace_file:
                        for line in strace_file:
                            line = list(line)
                            line.insert(17, ' [' + pid + ']')
                            line = "".join(line)
                            if '+++ exited with 0 +++' not in line and 'SIGCHLD' not in line:
                                merge_log.write(line)

    def merge_log(self):
        with open('hook_new.log', 'r') as hook_new:
            with open('merge.log', 'a') as merge_log:
                for line in hook_new:
                    merge_log.write(line)

    def sort_logs(self):
        logs = list()
        with open('merge.log', 'r') as merge_log:
            for line in merge_log:
                logs.append(line)
        logs.sort(key=get_time)
        with open('sort.log', 'w') as sort_log:
            for line in logs:
                line = line.replace("(nil)", "NULL")
                if "brk(" in line or "mmap(" in line or "munmap(" in line:
                    line = line.replace("(", "[").replace(")", "]")
                if 'free[NULL]' not in line:
                    sort_log.write(line)

    def pid2file(self):
        pid_re = re.compile(r'\[[1-9]\d*\]')
        with open('sort.log') as logs:
            for line in logs:
                pid_obj = pid_re.search(line).group()
                if pid_obj:
                    pid = re.findall(r'\d+', pid_obj)[0]
                    if pid:
                        with open(pid + '.log', 'a') as logfile:
                            logfile.write(line)

    def pre_processing(self):
        os.chdir(self.path)
        self.hook_pre()
        self.add_pid()
        self.merge_log()
        self.sort_logs()
        os.remove('merge.log')
        os.remove('hook_new.log')
        os.remove('hook.log')
        self.pid2file()
        for i in self.pids:
            os.remove('strace.' + i)
        os.remove('sort.log')
        os.chdir('../../')


class EvaL:

    PAGE_SIZE = 4096
    PROT_WRITE = 2

    def __init__(self, reserved_memory_glibc, allocated_glibc, allocated_ffmalloc, used_memory_glibc=None, heap_start_glibc=0, heap_break_glibc=0,
                 used_memory_ffmalloc=None, reserved_memory_ffmalloc=None, heap_start_ffmalloc=0, heap_break_ffmalloc=0,
                 keep_non_write=True):
        self.used_memory_glibc = used_memory_glibc
        self.reserved_memory_glibc = reserved_memory_glibc
        self.heap_start_glibc = heap_start_glibc
        self.heap_break_glibc = heap_break_glibc
        self.allocated_glibc = allocated_glibc

        self.used_memory_ffmalloc = used_memory_ffmalloc
        self.reserved_memory_ffmalloc = reserved_memory_ffmalloc
        self.heap_start_ffmalloc = heap_start_ffmalloc
        self.heap_break_ffmalloc = heap_break_ffmalloc
        self.allocated_ffmalloc = allocated_ffmalloc

        self.keep_non_write = keep_non_write

    def handle_call(self, allocator, log):
        if allocator == 'glibc':
            typ, args, ret, syslib = parse_log(log)

            if typ == 'brk' or typ == "sbrk":

                if '-1' in ret or 'ENOMEM' in ret:  # failed
                    return

                # for most of the time, brk/sbrk is not from program
                if syslib == "lib":
                    # print("a brk call from library?")
                    pass

                old_heap_break = self.heap_break_glibc

                if args[0] == "NULL" or args[0] == "0":

                    # if we have not seen the heap start, the program uses this
                    # brk(0) to get the beginning of the heap region
                    if self.heap_start_glibc == 0:
                        self.heap_break_glibc = self.heap_start_glibc = int(ret, 16)

                    # if we have seen the heap start, this brk(0) is only used
                    # to get the heap break (again)

                    return

                else:

                    if typ == 'brk':
                        self.heap_break_glibc = int(ret, 16)

                    else:
                        old_heap_break = int(ret, 16)
                        if old_heap_break != self.heap_break_glibc:
                            print("different heap break:", hex(old_heap_break),
                                  hex(self.heap_break_glibc))
                        self.heap_break_glibc = old_heap_break + int(args[0])

                if self.heap_break_glibc > old_heap_break:
                    self.add_to(self.reserved_memory_glibc,
                                old_heap_break, self.heap_break_glibc)
                elif self.heap_break_glibc < old_heap_break:
                    self.remove_from(self.reserved_memory_glibc,
                                     self.heap_break_glibc, old_heap_break)

            elif typ == 'mmap':

                # ignore mmap without PROT_WRITE permission
                if self.keep_non_write == False:
                    if syslib == "sys":
                        prot = args[2]
                        if "PROT_WRITE" not in prot:
                            return
                    elif syslib == "lib":
                        prot = int(args[2])
                        if prot & self.PROT_WRITE == 0:
                            return

                if ' -1 ' in ret or '0xffffffffffffffff' in ret or 'ENOMEM' in ret or 'EEXIST' in ret:
                    return
                start = int(ret, 16)
                size = int(args[1])
                size = int((((size - 1) // self.PAGE_SIZE) + 1)
                           * self.PAGE_SIZE)

                if syslib == "sys":
                    self.add_to(self.reserved_memory_glibc,
                                start, start + size)
                elif syslib == "lib":
                    self.add_to(self.used_memory_glibc, start, start + size)

            elif typ == 'munmap':

                start = int(args[0], 16)
                size = int(args[1])
                size = int((((size - 1) // self.PAGE_SIZE) + 1)
                           * self.PAGE_SIZE)

                if syslib == "sys":
                    self.remove_from(
                        self.reserved_memory_glibc, start, start + size)
                elif syslib == "lib":
                    self.remove_from(self.used_memory_glibc,
                                     start, start + size)

            elif typ == 'malloc' or typ == 'valloc':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[0])
                self.add_to(self.used_memory_glibc, start, start + size)
                self.allocated_glibc[start] = size

            elif typ == 'calloc':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[0]) * int(args[1])
                self.add_to(self.used_memory_glibc, start, start + size)
                self.allocated_glibc[start] = size

            elif typ == 'realloc' or typ == 'reallocarray':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                if args[0] == 'NULL':
                    old_ptr = 0
                else:
                    old_ptr = int(args[0], 16)

                new_ptr = int(ret, 16)
                old_size = new_size = 0

                if typ == 'realloc':
                    new_size = int(args[1])
                else:
                    new_size = int(args[1]) * int(args[2])

                if old_ptr in self.allocated_glibc:
                    old_size = self.allocated_glibc[old_ptr]
                elif old_ptr != 0:
                    print("Warnning: cannot find old allocation")
                    return

                if new_ptr == old_ptr:

                    self.allocated_glibc[new_ptr] = new_size

                    if old_size < new_size:
                        self.add_to(self.used_memory_glibc, old_ptr +
                                    old_size, new_ptr + new_size)
                    elif old_size > new_size:
                        self.remove_from(self.used_memory_glibc, new_ptr + new_size,
                                         old_ptr + old_size)

                else:
                    self.allocated_glibc[new_ptr] = new_size
                    self.allocated_glibc.pop(old_ptr, None)

                    self.remove_from(self.used_memory_glibc,
                                     old_ptr, old_ptr + old_size)
                    self.add_to(self.used_memory_glibc,
                                new_ptr, new_ptr + new_size)

            elif typ == 'memalign':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[1])
                self.add_to(self.used_memory_glibc, start, start + size)
                self.allocated_glibc[start] = size

            elif typ == 'posix_memalign':

                if ret[0] != '0':       # failed
                    return

                start = int(ret[1], 16)
                size = int(args[2])
                self.add_to(self.used_memory_glibc, start, start + size)
                self.allocated_glibc[start] = size

            elif typ == 'free':

                if args[0] == 'NULL':
                    return

                start = int(args[0], 16)
                size = 0
                if start in self.allocated_glibc:
                    size = self.allocated_glibc[start]
                else:
                    print("Warnning: cannot find old allocation")

                #print("free", hex(start), hex(start + size))
                self.remove_from(self.used_memory_glibc, start, start + size)
                self.allocated_glibc.pop(start, None)

            return

        else:
            typ, args, ret, syslib = parse_log(log)

            if typ == 'brk' or typ == "sbrk":

                if '-1' in ret or 'ENOMEM' in ret:  # failed
                    return

                # for most of the time, brk/sbrk is not from program
                if syslib == "lib":
                    # print("a brk call from library?")
                    pass

                old_heap_break = self.heap_break_ffmalloc

                if args[0] == "NULL" or args[0] == "0":

                    # if we have not seen the heap start, the program uses this
                    # brk(0) to get the beginning of the heap region
                    if self.heap_start_ffmalloc == 0:
                        self.heap_break_ffmalloc = self.heap_start_ffmalloc = int(
                            ret, 16)

                    # if we have seen the heap start, this brk(0) is only used
                    # to get the heap break (again)

                    return

                else:

                    if typ == 'brk':
                        self.heap_break_ffmalloc = int(ret, 16)

                    else:
                        old_heap_break = int(ret, 16)
                        if old_heap_break != self.heap_break_ffmalloc:
                            print("different heap break:", hex(old_heap_break),
                                  hex(self.heap_break_ffmalloc))
                        self.heap_break_ffmalloc = old_heap_break + int(args[0])

                if self.heap_break_ffmalloc > old_heap_break:
                    self.add_to(self.reserved_memory_ffmalloc,
                                old_heap_break, self.heap_break_ffmalloc)
                elif self.heap_break_ffmalloc < old_heap_break:
                    self.remove_from(self.reserved_memory_ffmalloc,
                                     self.heap_break_ffmalloc, old_heap_break)

            elif typ == 'mmap':

                # ignore mmap without PROT_WRITE permission
                if self.keep_non_write == False:
                    if syslib == "sys":
                        prot = args[2]
                        if "PROT_WRITE" not in prot:
                            return
                    elif syslib == "lib":
                        prot = int(args[2])
                        if prot & self.PROT_WRITE == 0:
                            return
                if ' -1 ' in ret or '0xffffffffffffffff' in ret or 'ENOMEM' in ret or 'EEXIST' in ret:
                    return
                start = int(ret, 16)
                size = int(args[1])
                size = int((((size - 1) // self.PAGE_SIZE) + 1)
                           * self.PAGE_SIZE)

                if syslib == "sys":
                    self.add_to(self.reserved_memory_ffmalloc,
                                start, start + size)
                elif syslib == "lib":
                    self.add_to(self.used_memory_ffmalloc, start, start + size)

            elif typ == 'munmap':

                start = int(args[0], 16)
                size = int(args[1])
                size = int((((size - 1) // self.PAGE_SIZE) + 1)
                           * self.PAGE_SIZE)

                if syslib == "sys":
                    self.remove_from(
                        self.reserved_memory_ffmalloc, start, start + size)
                elif syslib == "lib":
                    self.remove_from(self.used_memory_ffmalloc,
                                     start, start + size)

            elif typ == 'malloc' or typ == 'valloc':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[0])
                self.add_to(self.used_memory_ffmalloc, start, start + size)
                self.allocated_ffmalloc[start] = size

            elif typ == 'calloc':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[0]) * int(args[1])
                self.add_to(self.used_memory_ffmalloc, start, start + size)
                self.allocated_ffmalloc[start] = size

            elif typ == 'realloc' or typ == 'reallocarray':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                if args[0] == 'NULL':
                    old_ptr = 0
                else:
                    old_ptr = int(args[0], 16)

                new_ptr = int(ret, 16)
                old_size = new_size = 0

                if typ == 'realloc':
                    new_size = int(args[1])
                else:
                    new_size = int(args[1]) * int(args[2])

                if old_ptr in self.allocated_ffmalloc:
                    old_size = self.allocated_ffmalloc[old_ptr]
                elif old_ptr != 0:
                    print("Warnning: cannot find old allocation")
                    return

                if new_ptr == old_ptr:

                    self.allocated_ffmalloc[new_ptr] = new_size

                    if old_size < new_size:
                        self.add_to(self.used_memory_ffmalloc, old_ptr +
                                    old_size, new_ptr + new_size)
                    elif old_size > new_size:
                        self.remove_from(self.used_memory_ffmalloc, new_ptr + new_size,
                                         old_ptr + old_size)

                else:
                    self.allocated_ffmalloc[new_ptr] = new_size
                    self.allocated_ffmalloc.pop(old_ptr, None)

                    self.remove_from(self.used_memory_ffmalloc,
                                     old_ptr, old_ptr + old_size)
                    self.add_to(self.used_memory_ffmalloc,
                                new_ptr, new_ptr + new_size)

            elif typ == 'memalign':

                if 'NULL' in ret or '0' == ret:  # failed
                    return

                start = int(ret, 16)
                size = int(args[1])
                self.add_to(self.used_memory_ffmalloc, start, start + size)
                self.allocated_ffmalloc[start] = size

            elif typ == 'posix_memalign':

                if ret[0] != '0':       # failed
                    return

                start = int(ret[1], 16)
                size = int(args[2])
                self.add_to(self.used_memory_ffmalloc, start, start + size)
                self.allocated_ffmalloc[start] = size

            elif typ == 'free':

                if args[0] == 'NULL':
                    return

                start = int(args[0], 16)
                size = 0
                if start in self.allocated_ffmalloc:
                    size = self.allocated_ffmalloc[start]
                else:
                    print("Warnning: cannot find old allocation")

                #print("free", hex(start), hex(start + size))
                self.remove_from(self.used_memory_ffmalloc,
                                 start, start + size)
                self.allocated_ffmalloc.pop(start, None)

            return

    # add the new memory range [start, end) to the memory_set
    # this function guarantees that the memory ranges are sorted, unique,
    # and mutually exclusive. We also merge memory ranges if possible
    def add_to(self, memory_set, start, end):

        # print("before add_to:",)
        # print_memory_set(memory_set)
        # print("adding", hex(start), hex(end))
        # print(type(memory_set))
        # print("----------------------------------------------")

        if start >= end:
            print("wrong range to add_to:", hex(start), hex(end))
            return

        start_index = -1
        new_end = 0
        for index in range(0, len(memory_set)):

            [cur_start, cur_end] = memory_set[index]

            # [cur_start, cur_end] [start, end]
            if start > cur_end:
                continue

            # [start, end] [cur_start, cur_end]
            if end < cur_start:
                memory_set.insert(index, [start, end])
                # print_memory_set(memory_set)
                return

            else:
                memory_set[index][0] = min(cur_start, start)
                memory_set[index][1] = new_end = max(cur_end, end)

                start_index = index

            break

        if start_index == -1:
            memory_set.append([start, end])
            # print_memory_set(memory_set)
            return

        to_delete = []
        for index in range(start_index, len(memory_set)):

            [cur_start, cur_end] = memory_set[index]

            if new_end < cur_start:
                break

            memory_set[start_index][1] = new_end = max(cur_end, new_end)

            if index != start_index:
                to_delete.append(index)

        if len(to_delete) != 0:
            to_delete.reverse()
            for index in to_delete:
                memory_set.pop(index)

        # print_memory_set(memory_set)

    # remove the memory range [start, end) from the memory_set
    # this function just removes the overlap part of the given ragne and
    # existing ranges
    def remove_from(self, memory_set, start, end):

        # print("before remove_from:",)
        # print_memory_set(memory_set)
        # print("removing", hex(start), hex(end))
        # print("----------------------------------------------")

        if start >= end:
            if start == end == 0:
                return
            print("wrong range to remove_from:", hex(start), hex(end))
            return

        to_insert = []
        for index in range(0, len(memory_set)):

            [cur_start, cur_end] = memory_set[index]

            if start >= cur_end:
                continue

            # we are done since the ranges are sorted
            if end < cur_start:
                break

            updated = False
            if cur_start < start:
                # we will keep [cur_start, start]
                memory_set[index][1] = start
                updated = True

            if end < cur_end:
                # we will keep [end, cur_end]
                if updated == False:
                    memory_set[index][0] = end
                else:
                    to_insert.append([index + 1, end, cur_end])

            if cur_start == start and cur_end == end:
                memory_set.pop(index)

            break

        for index in reversed(range(0, len(to_insert))):
            memory_set.insert(to_insert[index][0],
                              [to_insert[index][1], to_insert[index][2]])

        # print_memory_set(memory_set)
    
    def calculate_diff(self):

        # data intialization
        reserved_memory_glibc_total = 0
        reserved_memory_ffmalloc_total = 0
        used_memory_glibc_total = 0
        used_memory_ffmalloc_total = 0

        if self.reserved_memory_glibc:
            for memory in self.reserved_memory_glibc:
                reserved_memory_glibc_total = reserved_memory_glibc_total + \
                    (memory[1]-memory[0])
            if self.reserved_memory_ffmalloc:
                for memory in self.reserved_memory_ffmalloc:
                    reserved_memory_ffmalloc_total = reserved_memory_ffmalloc_total + \
                        (memory[1]-memory[0])

        # calculate used memory
        if self.used_memory_glibc:
            for memory in self.used_memory_glibc:
                used_memory_glibc_total = used_memory_glibc_total + \
                    (memory[1]-memory[0])
        if self.used_memory_ffmalloc:
            for memory in self.used_memory_ffmalloc:
                used_memory_ffmalloc_total = used_memory_ffmalloc_total + \
                    (memory[1]-memory[0])

        return [reserved_memory_glibc_total, reserved_memory_ffmalloc_total], [used_memory_glibc_total, used_memory_ffmalloc_total]


def search_log(lib2all, log):
    try:
        index = lib2all[log]
    except Exception as e:
        return -1

    return index


def update_item(item, temp_item):
    if item == temp_item or temp_item == -1:
        return item
    else:
        return temp_item


def merge_sort_logs(logs, sub_logs0, sub_logs1):
    for i in sub_logs0:
        logs.append(i)
    for i in sub_logs1:
        if i not in logs:
            logs.append(i)
    logs.sort(key=get_time)

    return logs


def closest_index(myData, myNumber):
    tmp = []
    if isinstance(myData, dict):
        for key in myData.keys():
            if int(key) < myNumber:
                tmp.append(int(key))

        return myData[max(tmp)]

    elif isinstance(myData, list):
        for i in myData:
            if int(i) < myNumber:
                tmp.append(int(i))

        return max(tmp)


def get_time(line):
    return format(float(line.split(" ")[0]), '.6f')


def clean():
    os.system(
        'rm -f ./log/*/*.log ./log/*/strace.* strace.* *.pdf *.log ./log/*/* ./dumb/*')


# parse the log, get the system/library call function name, arguments and return values
def parse_log(line):
    typ = None
    args = []
    ret = []
    syslib = None

    # check function type
    if "brk[" in line and "sbrk[" not in line:
        typ = "brk"
    elif "mmap[" in line:
        typ = "mmap"
    elif "munmap[" in line:
        typ = "munmap"
    elif "sbrk[" in line:
        typ = "sbrk"
    elif "malloc[" in line:
        typ = "malloc"
    elif "calloc[" in line:
        typ = "calloc"
    elif "realloc[" in line:
        typ = "realloc"
    elif "reallocarray[" in line:
        typ = "reallocarray"
    elif "valloc[" in line:
        typ = "valloc"
    elif "memalign[" in line and 'posix_memalign[' not in line:
        typ = "memalign"
    elif "posix_memalign[" in line:
        typ = "posix_memalign"
    elif "free[" in line:
        typ = "free"
    else:
        print("unknow function call type:", line)
        exit(1)

    pattern = re.compile(r'\[(.*?)\]', re.S)
    start = line.find(typ + "[")
    func = line[start:].strip()

    if typ == "free":
        args = re.findall(pattern, func)

    elif typ == "posix_memalign":
        a = re.findall(pattern, func)
        args = a[0].split(", ")
        ret = func.split("= ")[1].split(", ")

    else:
        a = re.findall(pattern, func)
        args = a[0].split(", ")
        ret = func.split("= ")[1]

    # check function call type
    if "LIBHOOK_LOG" in line:
        syslib = "lib"
    else:
        syslib = "sys"

    return typ, args, ret, syslib


# link each free() with correspingding malloc()
def link_free(index, link_free_dic, log, log_size):
    typ, args, ret, syslib = parse_log(log)

    if typ in ['malloc', 'valloc']:
        addr = ret
        size = int(args[0])
        if log_size is True:
            if addr and size:
                link_free_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_free_dic.setdefault(str(addr), []).append(index)
    if typ in ['realloc', 'memalign']:
        addr = ret
        size = int(args[1])
        if log_size is True:
            if addr and size:
                link_free_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_free_dic.setdefault(str(addr), []).append(index)
    if typ == 'calloc':
        addr = ret
        size = int(args[0]) * int(args[1])
        if log_size is True:
            if addr and size:
                link_free_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_free_dic.setdefault(str(addr), []).append(index)
    if typ == 'posix_memalign':
        addr = ret
        size = int(args[2])
        if log_size is True:
            if addr and size:
                link_free_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_free_dic.setdefault(str(addr), []).append(index)
    if typ == 'reallocarray':
        addr = ret
        size = int(args[2])
        if log_size is True:
            if addr and size:
                link_free_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_free_dic.setdefault(str(addr), []).append(index)
            
    return link_free_dic


# link each munmap() with correspingding mmap()
def link_munmap(index, link_munmap_dic, log, log_size):
    typ, args, ret, syslib = parse_log(log)
    if typ == 'mmap' and syslib == 'lib':
        addr = ret
        size = int(args[1])
        if log_size is True:
            if addr and size:
                link_munmap_dic.setdefault(str(addr), {})[index] = size
        elif log_size is False:
            if addr:
                link_munmap_dic.setdefault(str(addr), []).append(index)
                
    return link_munmap_dic

# link each addr() with correspingding malloc/realloc/valloc
def link_addr(index, link_addr_dic, log):
    typ, args, ret, syslib = parse_log(log)
    if 'NULL' in ret or '0' == ret or ' -1 ' in ret or '0xffffffffffffffff' in ret or 'ENOMEM' in ret or 'EEXIST' in ret or ret is None:
        pass
    else:
        if typ == 'posix_memalign':
            addr = args[0]
        if typ == 'free':
            addr = args[0]
        else:
            addr = ret
        try:
            link_addr_dic.setdefault(str(addr), []).append(index)
        except TypeError as e:
            print(e)
            print(log)

    return link_addr_dic
