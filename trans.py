import time
import sys
import getopt
import os
import json
import re
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
import libeval
import subprocess

pids = []

used_memory_glibc = []           # used memory
reserved_memory_glibc = []     # reserved memory
used_memory_ffmalloc = []           # used memory
reserved_memory_ffmalloc = []     # reserved memory
allocated_glibc = {} 
allocated_ffmalloc = {} 

# dumb_glibc_headers = '''
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <sys/types.h>
# #include <sys/mman.h>
# #include <malloc.h>
# #include <unistd.h>
# #include <sys/syscall.h>
# #include <sys/stat.h>
# long unsigned int get_vmsize() {
#     long unsigned int vsize;
#     char filename[24];
#     int current_pid = syscall(SYS_gettid);
#     sprintf(filename, "/proc/%d/stat", current_pid);
#     FILE *f = fopen(filename, "r");
#     if(f == NULL) { exit(1); }
#     fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d%*u %lu", &vsize);
#     fclose(f);
#     return vsize;
# }
# int main(int argc, char *argv[]) {'''

# dumb_glibc_headers = '''\
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <sys/types.h>
# #include <sys/mman.h>
# #include <malloc.h>
# #include <unistd.h>
# #include <sys/syscall.h>
# #include <sys/stat.h>
# #include <fcntl.h>
# int count = 0;
# long unsigned int get_vmsize() {
#     int current_pid = syscall(SYS_gettid);
#     char filename[24];
#     sprintf(filename, "/proc/%d/stat", current_pid);
#     char cmd[100];
#     sprintf(cmd, "cp /proc/%d/stat ./%d", current_pid, count);
#     system(cmd);
#     char new_filename[40];
#     sprintf(new_filename, "./%d", count);
#     int fd = open(new_filename, O_RDONLY);
#     if(fd == -1) {
#         fprintf(stdout, "can not open the file!\\n");
#         exit(-1);
#     }
#     struct stat file_stat;
#     int file_stat_no = fstat(fd, &file_stat);
#     if(file_stat_no == -1) {
#       fprintf(stdout, "can not get the size of the file!\\n");
#       close(fd);
#       exit(-1);
#     }
#     int len = file_stat.st_size;
#     void* ptr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0); 
#     if(ptr == NULL || ptr == (void*)-1){
#       fprintf(stdout, "mmap failed!\\n");
#       close(fd);
#       exit(-1);
#     }  
#     long unsigned int vsize;
#     sscanf(ptr, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %*u %lu", &vsize);
#     munmap(ptr, len);
#     close(fd);
#     sprintf(cmd, "rm -f ./%d", count);
#     system(cmd);
#     count++;
#     return vsize;
# }
# int main(int argc, char *argv[]) {\n'''

dumb_glibc_headers = '''\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

long unsigned int get_vmsize() {
    int current_pid = syscall(SYS_gettid);
    char filename[24];
    sprintf(filename, "/proc/%d/stat", current_pid);
    int fd, size;
    char buffer[1000];
    fd = open(filename, O_RDONLY);
    size = read(fd, buffer, sizeof(buffer));
    close(fd);
    long unsigned int vsize;
    sscanf(buffer, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %*u %lu", &vsize);
    return vsize;
}
int main(int argc, char *argv[]) {\n'''

dumb_glibc_headers = '''\
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

char* itoa(int val, int base) {
    static char buf[32] = {0};
    int i = 30;
    for(; val && i ; --i, val /= base)
        buf[i] = "0123456789abcdef"[val % base];
    return &buf[i+1];
}

void concatenate(char *str1, char *str2)
{
    int i = strlen(str1), j = 0;
    while (str2[j] != '\\0')
    {
        str1[i] = str2[j];
        i++;
        j++;
    }
    str1[i] = '\\0';  // declaring the end of the string
}

char* get_vmsize()
{
    int current_pid = syscall(SYS_gettid);
    char ch0[] = "/proc/";
    char ch1[] = "/stat";
    int fd;
    char buffer[1000];
    char* filename;
    concatenate(ch0, itoa(current_pid, 10));
    concatenate(ch0, ch1);
    fd = open(ch0, O_RDONLY);
    read(fd, buffer, sizeof(buffer));
    close(fd);
    int count = 0;
    int pos = 0;
    int start, end;
    while (count < 23) {
        if(buffer[pos] == ' ')
            count++;
        pos++;
        if(count==21){start = pos+1;}
        if(count==22){
            end = pos;
        }
    }
    char vsize[32];
    int j = 0;
    for(int i=start;i<end;i++){
        vsize[j] = buffer[i];
        j++;
    }
    vsize[end-start] = '\\n';
	vsize[end-start+1] = '\\0';
    write(STDERR_FILENO, vsize, strlen(vsize));
}

int main(int argc, char *argv[]) {\n'''


dumb_calculate_reserved = '\tget_vmsize();\n'


def translate_log2program(ffmalloc_path):
    print("------------------------translate glibc logs to C programs-------------------------")
    files_glibc = []
    filelist_tmp = os.listdir('./log/glibc')
    for file in filelist_tmp:
        files_glibc.append(file)
    files_glibc.sort(key=lambda x: int(x.split('.')[0]))
    if len(files_glibc) == 0:
        print('0 log generated, failed!')
        return

    for i in range(len(files_glibc)):
        # all logs
        logs_glibc = []
        # libhook logs
        libhook_logs_glibc = []
        libhook_logs_glibc_dict = {}

        # reserved memory and diff
        glibc_result = []

        # link list of free() and munmap()
        glibc_free_dict = {}
        glibc_munmap_dict = {}

        # link the return address with corresponding operations
        glibc_addr2opt_dict = {}

        # get the index of an library call log in all logs
        glibc_lib2all = {}

        # data for drawing the figure

        file_glibc = open('./log/glibc/'+files_glibc[i], 'r')
        dumb_glibc_filename = './dumb/dumb_glibc_'+files_glibc[i].split('.')[0]+'.c'
        file_ffmalloc = open(dumb_glibc_filename, 'a')
        file_ffmalloc.write(dumb_glibc_headers)

        all_index = 0
        libhook_index = 0

        eval_glibc = libeval.EvaL(used_memory_glibc=used_memory_glibc, reserved_memory_glibc=reserved_memory_glibc, allocated_glibc=allocated_glibc, allocated_ffmalloc=allocated_ffmalloc)
        for log in file_glibc:
            logs_glibc.append(log)
            eval_glibc.handle_call('glibc', log)
            if 'LIBHOOK_LOG' in log:
                libhook_logs_glibc_dict[log] = libhook_index
                libhook_logs_glibc.append(log)
                glibc_free_dict = libeval.link_free(libhook_index, glibc_free_dict, log, False)
                glibc_munmap_dict = libeval.link_munmap(libhook_index, glibc_munmap_dict, log, False)
                glibc_addr2opt_dict = libeval.link_addr(libhook_index, glibc_addr2opt_dict, log)
                glibc_lib2all[log] = all_index
                glibc_result.append(eval_glibc.calculate_diff()[0][0])
                libhook_index += 1
            all_index = all_index + 1
        file_glibc.close()

        for cursor in range(len(libhook_logs_glibc)):
            typ, args, ret, syslib = libeval.parse_log(libhook_logs_glibc[cursor])
            if typ == 'malloc':
                dumb_log = "\tvoid* p{} = malloc({});\n".format(cursor, args[0])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'free': 
                if args[0] == 'NULL':
                    dumb_log = "\tfree(NULL);\n"
                else:
                    ptr_index = libeval.closest_index(glibc_free_dict[args[0]], cursor)
                    # print(glibc_free_dict[args[0]], ptr_index, cursor)
                    dumb_log = "\tfree(p{});\n".format(ptr_index)
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'realloc':
                if args[0] == 'NULL':
                    dumb_log = "\tvoid* p{} = realloc(NULL, {});\n".format(cursor, args[1])
                else:
                    ptr_index = libeval.closest_index(glibc_addr2opt_dict[args[0]], cursor)
                    dumb_log = "\tvoid* p{} = realloc(p{}, {});\n".format(cursor, ptr_index, args[1])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'calloc':
                dumb_log = "\tvoid* p{} = calloc({}, {});\n".format(cursor, args[0], args[1])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'valloc':
                dumb_log = "\tvoid* p{} = valloc({});\n".format(cursor, args[0])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'memalign':
                dumb_log = "\tvoid* p{} = memalign({}, {});\n".format(cursor, args[0], args[1])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'posix_memalign':
                if args[0] == 'NULL':
                    dumb_log = "\tint v{} = posix_memalign(NULL, {}, {});\n".format(cursor, args[1], args[2])
                else:
                    ptr_index = libeval.closest_index(glibc_addr2opt_dict[args[0]], cursor)
                    dumb_log = "\tint v{} = posix_memalign(p{}, {}, {});\n".format(cursor, ptr_index, args[1], args[2])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'reallocarray':
                ptr_index = libeval.closest_index(glibc_addr2opt_dict[args[0]], cursor)
                dumb_log = "\tvoid* p{} = reallocarray(p{}, {}, {});\n".format(cursor, ptr_index, args[1], args[2])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'mmap':
                if args[0] == 'NULL':
                    dumb_log = "\tvoid* p{} = mmap(NULL, {}, {}, {}, {}, {});\n".format(cursor, args[1], args[2], args[3], args[4], args[5])
                else:
                    ptr_index = libeval.closest_index(glibc_addr2opt_dict[args[0]], cursor)
                    dumb_log = "\tvoid* p{} = mmap({}, {}, {}, {}, {}, {});".format(cursor, args[0], args[1], args[2], args[3], args[4], args[5])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'munmap':
                ptr_index = libeval.closest_index(glibc_munmap_dict[args[0]], cursor)
                dumb_log = "\tmunmap(p{}, {});\n".format(ptr_index, args[1])
                file_ffmalloc.write(dumb_log)
                file_ffmalloc.write(dumb_calculate_reserved)
            if typ == 'sbrk' :
                if args[0] == '0':
                    dumb_log = "\tsbrk(0);\n"
                    file_ffmalloc.write(dumb_log)
                    file_ffmalloc.write(dumb_calculate_reserved)

        file_ffmalloc.write('\treturn 0;\n')
        file_ffmalloc.write('}')
        file_ffmalloc.close()
        os.system("gcc -g -o {bin_name} {cname}".format(bin_name=dumb_glibc_filename.split('.c')[0], cname=dumb_glibc_filename))
        bin_path = os.path.join(os.getcwd()+dumb_glibc_filename[1:].split('.c')[0])
        
        cmd_ffmalloc = 'LD_PRELOAD={} {} 2>./log/ffmalloc/hook_{}.log' \
        .format(ffmalloc_path, bin_path, i)
        print(cmd_ffmalloc)
        task_ffmalloc = subprocess.Popen(cmd_ffmalloc, shell=True)
        task_ffmalloc.wait()

        cmd_dumb_glibc = '{} 2>./log/glibc/hook_{}.log' \
        .format(bin_path, i)
        print(cmd_dumb_glibc)
        task_dumb_glibc = subprocess.Popen(cmd_dumb_glibc, shell=True)
        task_dumb_glibc.wait()

        ffmalloc_result = []
        dumb_glibc_result = []

        with open('./log/ffmalloc/hook_{}.log'.format(i), 'r') as ffmalloc_result_file:
            for line in ffmalloc_result_file:
                # ffmalloc_result.append(int(line.split(' = ')[1]))
                # ffmalloc_result.append(int(filter(str.isdigit, line)))
                ffmalloc_result.append(int(line))

        with open('./log/glibc/hook_{}.log'.format(i), 'r') as glibc_result_file:
            for line in glibc_result_file:
                # dumb_glibc_result.append(int(line.split(' = ')[1]))
                # dumb_glibc_result.append(int(filter(str.isdigit, line)))
                dumb_glibc_result.append(int(line))

        for num in range(len(glibc_result)):
            reserved_memory_glibc_total = glibc_result[num]
            reserved_memory_ffmalloc_total = ffmalloc_result[num]
            reserved_memory_dumb_glibc_total = dumb_glibc_result[num]
            print("g_rsv: %d, ff_rsv: %d, dm_g_rsv: %d ff_rsv/g_rsv: %.2f ff_rsv/dm_g_rsv: %.2f g_rsv/dmg_rsv: %.2f" \
             % (reserved_memory_glibc_total, reserved_memory_ffmalloc_total, reserved_memory_dumb_glibc_total, \
                reserved_memory_ffmalloc_total/reserved_memory_glibc_total, \
                reserved_memory_ffmalloc_total/reserved_memory_dumb_glibc_total, \
                reserved_memory_glibc_total/reserved_memory_dumb_glibc_total))


def usage():
    tab = '\t'
    print('Usage:')
    print(tab + 'python3 %s [OPTIONS]' % __file__)
    print(tab + '-l | --libhook_path=')
    print(tab * 2 + 'please use absolute path')
    print(tab + '-f | --ffmalloc_path=')
    print(tab * 2 + 'please use absolute path')
    print(tab + '-p | --program=')
    print(tab * 2 + 'please use absolute path')
    print(tab + '-c | --clean')
    print(tab * 2 + 'remove logs')


def main(argv):
    start0 = time.time()
    global non_write
    if not os.path.exists('./log/glibc'):
        os.mkdir('./log/glibc')
    if not os.path.exists('./log/ffmalloc'):
        os.mkdir('./log/ffmalloc')
    libhook_path = '/home/ziyu/research_project/eval-malloc/libhook/libhook.so'
    ffmalloc_path = '/home/ziyu/research_project/ffmalloc/libffmallocnpst.so'
    program = 'ls'
    try:
        opts, args = getopt.getopt(argv, 'hcnl:f:p:', [
                                   'help', 'clean', 'non_write', 'libhook_path=', 'ffmalloc_path=', 'program='])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-l', '--libhook_path'):
            libhook_path = arg
        elif opt in ('-f', '--ffmalloc_path'):
            ffmalloc_path = arg
        elif opt in ('-p', '--program'):
            program = arg
        elif opt in ('-c', '--clean'):
            libeval.clean()
            sys.exit(0)
        elif opt in ('-n', '--non_write'):
            non_write = True
        elif opt in ('-h', '--help'):
            usage()
            sys.exit(0)
    if libhook_path is None or ffmalloc_path is None or program is None:
        usage()
        sys.exit(1)
    if not os.path.exists(libhook_path):
        print('wrong libhook path: %s' % libhook_path)
        sys.exit(1)
    if not os.path.exists(ffmalloc_path):
        print('wrong ffmalloc path: %s' % ffmalloc_path)
        sys.exit(1)

    os.system('LD_PRELOAD={} strace -e trace=mmap,munmap,brk -f -ff -o ./log/glibc/strace -ttt {} 2>./log/glibc/hook.log'.format(libhook_path, program))

    logs_pre_glibc = libeval.PreLog('./log/glibc', pids)
    logs_pre_glibc.pre_processing()
    
    translate_log2program(ffmalloc_path)

    end0 = time.time()

    print("time used: %.2f seconds" %(end0-start0))
    


if __name__ == '__main__':
    main(sys.argv[1:])
