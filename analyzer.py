# export MALLOC_ARENA_MAX=1
import os
import sys
import re
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.animation as animation
import matplotlib.ticker as ticker
import matplotlib.backends.backend_pdf
import cv2
import argparse
import time

pids = []
plt.rcParams["font.family"] = "monospace"
PAGE_SIZE = 4096

def print_memory_set(memory_set):
    for start, end in memory_set:
        print ('(' + hex(start) + ', ' +  hex(end) + ')')


def print_array(arr):
    for val in arr:
        print (hex(val),)
    print()


def print_array_array(arr):
    for val in arr:
        print_array(val)
    print()


def get_time(line):
    return format(float(line.split(" ")[0]), '.6f')


def hook_pre():
    pid_re = re.compile(r'\[[1-9]\d*\]')
    global pids
    pids = list()
    files = os.listdir(os.getcwd())
    for i in files:
        if "strace" in i:
            pids.append(i.split(".")[1])
    with open("hook.log", 'r') as hook_file:
        with open("hook_new.log", 'w') as hook_new:
            for line in hook_file:
                pid_obj = pid_re.search(line).group()
                if pid_obj:
                    if re.findall(r'\d+', pid_obj)[0] not in pids:
                        pass
                    else:
                        hook_new.write(line)
                else:
                    pass


def add_pid():
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

            else:
                pass


def merge_log():
    with open('hook_new.log', 'r') as hook_new:
        with open('merge.log', 'a') as merge_log:
            for line in hook_new:
                merge_log.write(line)


def sort_logs():
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
            sort_log.write(line)


def pid2file():
    pid_re = re.compile(r'\[[1-9]\d*\]')
    with open('sort.log') as logs:
        for line in logs:
            pid_obj = pid_re.search(line).group()
            if pid_obj:
                pid = re.findall(r'\d+', pid_obj)[0]
                if pid:
                    with open(pid + '.log', 'a') as logfile:
                        logfile.write(line)
            else:
                pass


def pre_processing():
    global pids
    os.chdir("./log")
    hook_pre()
    add_pid()
    merge_log()
    sort_logs()
    os.remove('merge.log')
    os.remove('hook_new.log')
    os.remove('hook.log')
    pid2file()
    for i in pids:
        os.remove('strace.' + i)
    # os.remove('sort.log')


# parse the log, get the system/library call function name, arguments and return values
def parse_log(line):
    typ = None
    args = []
    ret = []
    syslib = None

    # check function type
    if "brk[" in line:
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


# add the new memory range [start, end) to the memory_set
# this function guarantees that the memory ranges are sorted, unique,
# and mutually exclusive. We also merge memory ranges if possible
def add_to(memory_set, start, end):
    
    #print ("before add_to:",)
    #print_memory_set(memory_set)
    #print ("adding", hex(start), hex(end))
    #print (type(memory_set))
    #print ("----------------------------------------------")

    if start >= end:
        print ("wrong range to add_to:", hex(start), hex(end))
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
            #print_memory_set(memory_set)
            return

        else:
            memory_set[index][0] = min(cur_start, start)
            memory_set[index][1] = new_end = max(cur_end, end)

            start_index = index

        break

    if start_index == -1:
        memory_set.append([start, end])
        #print_memory_set(memory_set)
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

    #print_memory_set(memory_set)


# remove the memory range [start, end) from the memory_set
# this function just removes the overlap part of the given ragne and
# existing ranges
def remove_from(memory_set, start, end):

    #print ("before remove_from:",)
    #print_memory_set(memory_set)
    #print ("removing", hex(start), hex(end))
    #print ("----------------------------------------------")

    if start >= end:
        if start == end == 0:
            return
        print ("wrong range to remove_from:", hex(start), hex(end))
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

    #print_memory_set(memory_set)


used_memory = []            # used memory
reserved_memory = []        # reserved memory
heap_start = 0
heap_break = 0
allocated = {}              # address -> alocation size

PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

def handle_call(log, keep_non_write):

    global used_memory
    global reserved_memory
    global heap_start
    global heap_break
    global allocated

    print (log.strip())
    typ, args, ret, syslib = parse_log(log)

    if typ == 'brk' or typ == "sbrk":

        if '-1' in ret or 'ENOMEM' in ret:  # failed
            return

        # for most of the time, brk/sbrk is not from program
        if syslib == "lib":
            print ("a brk call from library?")
            # exit(1)

        old_heap_break = heap_break

        if args[0] == "NULL" or args[0] == "0":

            # if we have not seen the heap start, the program uses this
            # brk(0) to get the beginning of the heap region
            if heap_start == 0:
               heap_break = heap_start = int(ret, 16)

            # if we have seen the heap start, this brk(0) is only used
            # to get the heap break (again)

            return

        else:

            if typ == 'brk':
                heap_break = int(ret, 16)

            else:
                old_heap_break = int(ret, 16)
                if old_heap_break != heap_break:
                    print ("different heap break:", hex(old_heap_break),
                            hex(heap_break))
                heap_break = old_heap_break + int(args[0])

        if heap_break > old_heap_break:
            add_to(reserved_memory, old_heap_break, heap_break)
        elif heap_break < old_heap_break:
            remove_from(reserved_memory, heap_break, old_heap_break)

    elif typ == 'mmap':

        # ignore mmap without PROT_WRITE permission
        if keep_non_write == False:
            if syslib == "sys":
                prot = args[2]
                if "PROT_WRITE" not in prot:
                    return
            elif syslib == "lib":
                prot = int(args[2])
                if prot & PROT_WRITE == 0:
                    return

        start = int(ret, 16)
        size = int(args[1])
        size = int((((size - 1) // PAGE_SIZE) + 1) * PAGE_SIZE)

        if syslib == "sys":
            add_to(reserved_memory, start, start + size)
        elif syslib == "lib": 
            add_to(used_memory, start, start + size)

    elif typ == 'munmap':

        start = int(args[0], 16)
        size = int(args[1])
        size = int((((size - 1) // PAGE_SIZE) + 1) * PAGE_SIZE)

        if syslib == "sys":
            remove_from(reserved_memory, start, start + size)
        elif syslib == "lib": 
            remove_from(used_memory, start, start + size)

    elif typ == 'malloc' or typ == 'valloc':

        if 'NULL' in ret or '0' == ret: # failed
            return

        start = int(ret, 16)
        size = int(args[0])
        add_to(used_memory, start, start + size)
        allocated[start] = size

    elif typ == 'calloc':

        if 'NULL' in ret or '0' == ret: # failed
            return

        start = int(ret, 16)
        size = int(args[0]) * int(args[1])
        add_to(used_memory, start, start + size)
        allocated[start] = size

    elif typ == 'realloc' or typ == 'reallocarray':

        if 'NULL' in ret or '0' == ret: # failed
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

        if old_ptr in allocated:
            old_size = allocated[old_ptr]
        elif old_ptr != 0:
            print("Warnning: cannot find old allocation")
            return

        if new_ptr == old_ptr:

            allocated[new_ptr] = new_size

            if old_size < new_size:
                add_to(used_memory, old_ptr + old_size, new_ptr + new_size)
            elif old_size > new_size:
                remove_from(used_memory, new_ptr + new_size, 
                        old_ptr + old_size)

        else:
            allocated[new_ptr] = new_size
            allocated.pop(old_ptr, None)

            remove_from(used_memory, old_ptr, old_ptr + old_size)
            add_to(used_memory, new_ptr, new_ptr + new_size)

    elif typ == 'memalign':

        if 'NULL' in ret or '0' == ret: # failed
            return

        start = int(ret, 16)
        size = int(args[1])
        add_to(used_memory, start, start + size)
        allocated[start] = size

    elif typ == 'posix_memalign':

        if ret[0] != '0':       # failed
            return

        start = int(ret[1], 16)
        size = int(args[2])
        add_to(used_memory, start, start + size)
        allocated[start] = size

    elif typ == 'free':

        if args[0] == 'NULL':
            return

        start = int(args[0], 16)
        size = 0
        if start in allocated:
            size = allocated[start]
        else:
            print("Warnning: cannot find old allocation")

        #print ("free", hex(start), hex(start + size))
        remove_from(used_memory, start, start + size)
        allocated.pop(start, None)

    return


def split_memory_set(memory_set, alignment):

    new_memory_set = []

    for memory in memory_set:

        [start, end] = memory

        if start // alignment == end // alignment:
            new_memory_set.append(memory)

        elif start // alignment > end // alignment: 
            print ("Wrong memory:", hex(start), hex(end))

        else:
            low = start // alignment
            high = (end - 1) // alignment
            new_memory_set.append([start, (low + 1) * alignment])
            for mid in range(low + 1, high):
                new_memory_set.append([mid * alignment, (mid + 1) * alignment])
            new_memory_set.append([high * alignment, end])

    return new_memory_set


def set_ax(ax, y_min, y_max, scale, yticks_value, yticks_string):

    #print(hex(int(y_min)), hex(int(y_max)))
    ax.set_ylim(y_min, y_max)
    ax.set_xlim(0, scale)
    # force not to use scientific expression
    ax.ticklabel_format(useOffset=False)
    # show x/yticks in hex
    ax.get_yaxis().set_major_formatter(ticker.FuncFormatter(to_hex))
    ax.get_xaxis().set_major_formatter(ticker.FuncFormatter(to_hex))
    # disable all boundaries
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    ax.invert_yaxis()
    ax.set_xticks(np.arange(0, scale, PAGE_SIZE))
    ax.set_yticks(yticks_value)
    ax.set_yticklabels(yticks_string)
    ax.grid(which='major', axis='x', linewidth=.5)
    ax.set_xticklabels([]) 
    ax.tick_params(length=0)


def draw_fig(reserved_memory, used_memory, scale, outfile):

    used = split_memory_set(used_memory, scale)
    reserved = split_memory_set(reserved_memory, scale)

    print("used_memory:")
    print_memory_set(used_memory)
    print("reserved_memory:")
    print_memory_set(reserved_memory)

    fig = plt.figure()
    plt.tight_layout()
    ax = fig.add_subplot(111)

    y_min = 1 << 48
    y_max = 0
    yticks_value = []
    yticks_string = []
    line_index = 1

    old_rect_y_mid = rect_y_mid = 0
    rect_height = 0.8 * scale

    y_to_index = []

    overlap = set(tuple(i) for i in reserved).intersection(
            set(tuple(i) for i in used))

    print(overlap)

    for memory in reserved:

        # visual effect
        old_rect_y_mid = rect_y_mid
        rect_y_mid = memory[0] // scale * scale
        rect_x_start = memory[0] - rect_y_mid

        if old_rect_y_mid != 0:
            if rect_y_mid == old_rect_y_mid + scale:
                line_index += 1
            elif rect_y_mid > old_rect_y_mid + scale:
                line_index += 2

        # real values
        line_mid = line_index * scale
        line_start = line_mid - rect_height // 2 

        if tuple(memory) not in overlap:
            #print ("reserved", hex(memory[0]), hex(memory[1]-memory[0]))
            rect = plt.Rectangle((rect_x_start, line_start), width=memory[1]-memory[0], 
                    height=rect_height, facecolor='lightgreen', linewidth=0)
            ax.add_patch(rect)

        yticks_value.append(line_mid)
        yticks_string.append(hex(rect_y_mid))

        y_min = min(y_min, line_start)
        y_max = max(y_max, line_start + rect_height)

        y_to_index.append([rect_y_mid, line_index])

    for memory in used:

        # visual effect
        rect_y_mid = memory[0] // scale * scale
        rect_x_start = memory[0] - rect_y_mid

        for v in y_to_index:
            if v[0] <= rect_y_mid < v[0] + scale:
                line_index = v[1]
                break
        else:
            print ("cannot find used in reserved: used", hex(int(rect_y_mid)),\
                    hex(int(memory[0])), hex(int(memory[1])))

        # real values
        line_mid = line_index * scale
        line_start = line_mid - rect_height // 2 

        #print ("used", hex(memory[0]), hex(memory[1]-memory[0]))
        rect = plt.Rectangle((rect_x_start, line_start), width=memory[1]-memory[0], 
                height=rect_height, facecolor='orangered', linewidth=0)
        ax.add_patch(rect)

    set_ax(ax, y_min, y_max, scale, yticks_value, yticks_string)
    fig.set_size_inches(40 * 0.5, 5 + line_index * 0.2, forward=True)

    start = time.time()
    outfile.savefig(fig)
    #plt.savefig(fname)
    print(time.time() - start)

    plt.close(fig)

    return


def analyze(filename, line_n, scale, keep_non_write, step):

    global used_memory, reserved_memory

    scale = PAGE_SIZE* scale
    line_n = (1 << 31) if line_n == 0 else line_n
    pdf = matplotlib.backends.backend_pdf.PdfPages("test.pdf")

    with open(filename, 'r') as log_file:
        for index in range(0, line_n):
            log = log_file.readline()
            if len(log) == 0:
                break
            handle_call(log, keep_non_write)
            
            if step == True:
                draw_fig(reserved_memory, used_memory, scale, pdf)

    if step == False:
        draw_fig(reserved_memory, used_memory, scale, pdf)

    pdf.close()

    return


def to_hex(x, pos):
    return '%x' % int(x)


def pic2video():
    os.chdir('./fig')
    dirpath = os.getcwd()
    filelist = os.listdir(dirpath)
    filelist.sort(key=embedded_numbers)
    img = cv2.imread(filelist[0])
    imgInfo = img.shape
    size = (imgInfo[1], imgInfo[0])
    video = cv2.VideoWriter('../pttest.avi', 0, 1, size)

    for item in filelist:
        if item.endswith('.pdf'):
            print(item)
            img = cv2.imread(item)
            video.write(img)
    video.release()


def embedded_numbers(list):
    re_digits = re.compile(r'(\d+)')
    pieces = re_digits.split(list)
    pieces[1::2] = map(int, pieces[1::2])
    return pieces


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--preprocess",     "-P", help="merge libcall and syscall files", action="store_true")
    parser.add_argument("--mergedfile",     "-m", help="path to merged log file")
    parser.add_argument("--topline",        "-n", help="first N lines to process", default=0, type=int)
    parser.add_argument("--pageline",       "-p", help="number of pages per line", default=8, type=int)
    parser.add_argument("--keepnonwrite",   "-k", help="keep non-writeable allocation", action="store_true")
    parser.add_argument("--step",                 help="create output files step by step", action="store_true")

    parser.add_argument("--libcallfile",    "-l", help="path to library call log file")
    parser.add_argument("--syscallfile",    "-s", help="path to system call log file")
    parser.add_argument("--pid",            "-i", help="process id to process", default=0, type=int)
    args = parser.parse_args()

    if args.preprocess:
        pre_processing()
        exit()

    if args.mergedfile != None:
        analyze(args.mergedfile, args.topline, args.pageline, args.keepnonwrite, args.step)
        exit()
