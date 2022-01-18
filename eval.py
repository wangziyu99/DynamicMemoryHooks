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

pids = []

used_memory_glibc = []           # used memory
reserved_memory_glibc = []     # reserved memory
heap_start_glibc = 0
heap_break_glibc = 0
allocated_glibc = {}              # address -> alocation size

used_memory_ffmalloc = []           # used memory
reserved_memory_ffmalloc = []     # reserved memory
heap_start_ffmalloc = 0
heap_break_ffmalloc = 0
allocated_ffmalloc = {}              # address -> alocation size

PROT_WRITE = 2


def eval_reserved_memory():
    print("------------------------evaluate reserved memory-------------------------")
    files_glibc = []
    files_ffmalloc = []
    filelist_tmp = os.listdir('./log/glibc')
    for file in filelist_tmp:
        files_glibc.append(file)
    files_glibc.sort(key=lambda x: int(x.split('.')[0]))
    filelist_tmp = os.listdir('./log/ffmalloc')
    for file in filelist_tmp:
        files_ffmalloc.append(file)
    files_ffmalloc.sort(key=lambda x: int(x.split('.')[0]))

    if len(files_glibc) != len(files_ffmalloc):
        print('different amount of threads!')
        return
    if len(files_glibc) == 0:
        print('0 log generated, failed!')
        return

    fig = plt.figure()
    ax = [0] * len(files_glibc)

    for i in range(len(files_glibc)):
        ax[i] = fig.add_subplot(len(files_glibc), 1, i+1)

        # all logs
        logs_glibc = []
        logs_ffmalloc = []
        # libhook logs
        libhook_logs_glibc = []
        libhook_logs_ffmalloc = []
        aligned_ffmalloc_logs = []

        # reserved memory and diff
        glibc_result = {}
        ffmalloc_result = {}

        # link list of free() and munmap()
        glibc_free_dict = {}
        ffmalloc_free_dict = {}
        glibc_munmap_dict = {}
        ffmalloc_munmap_dict = {}

        # get the index of an library call log in all logs
        glibc_lib2all = {}
        ffmalloc_lib2all = {}

        # data for drawing the figure

        print("------------------------log/glibc/%s log/ffmalloc/%s-------------------------" %
              (files_glibc[i], files_ffmalloc[i]))

        file_glibc = open('./log/glibc/'+files_glibc[i], 'r')
        file_ffmalloc = open('./log/ffmalloc/'+files_ffmalloc[i], 'r')

        temp_index = 0

        eval_glibc = libeval.EvaL(used_memory_glibc=used_memory_glibc, reserved_memory_glibc=reserved_memory_glibc, heap_start_glibc=heap_start_glibc, heap_break_glibc=heap_break_glibc,
        allocated_glibc=allocated_glibc, used_memory_ffmalloc=used_memory_ffmalloc, reserved_memory_ffmalloc=reserved_memory_ffmalloc, heap_start_ffmalloc=heap_start_ffmalloc,
        heap_break_ffmalloc=heap_break_ffmalloc, allocated_ffmalloc=allocated_ffmalloc)
        eval_ffmalloc = libeval.EvaL(used_memory_glibc=used_memory_glibc, reserved_memory_glibc=reserved_memory_glibc, heap_start_glibc=heap_start_glibc, heap_break_glibc=heap_break_glibc,
        allocated_glibc=allocated_glibc, used_memory_ffmalloc=used_memory_ffmalloc, reserved_memory_ffmalloc=reserved_memory_ffmalloc, heap_start_ffmalloc=heap_start_ffmalloc,
        heap_break_ffmalloc=heap_break_ffmalloc, allocated_ffmalloc=allocated_ffmalloc)
        for log in file_glibc:
            logs_glibc.append(log)
            eval_glibc.handle_call('glibc', log)
            if 'LIBHOOK_LOG' in log:
                libhook_logs_glibc.append(log)
                glibc_free_dict = libeval.link_free(temp_index, glibc_free_dict, log, True)
                glibc_munmap_dict = libeval.link_munmap(temp_index, glibc_munmap_dict, log, True)
                glibc_lib2all[log] = temp_index
                glibc_result[temp_index] = eval_glibc.calculate_diff()[0][0]
            temp_index = temp_index + 1
        temp_index = 0
        for log in file_ffmalloc:
            logs_ffmalloc.append(log)
            eval_ffmalloc.handle_call('ffmalloc', log)
            ffmalloc_result[temp_index] = eval_ffmalloc.calculate_diff()[0][1]
            if 'LIBHOOK_LOG' in log:
                libhook_logs_ffmalloc.append(log)
                ffmalloc_free_dict = libeval.link_free(temp_index, ffmalloc_free_dict, log, True)
                ffmalloc_munmap_dict = libeval.link_munmap(temp_index, ffmalloc_munmap_dict, log, True)
                ffmalloc_lib2all[log] = temp_index
            temp_index = temp_index + 1

        file_glibc.close()
        file_ffmalloc.close()

        valid_result_index = 0
        # calculate
        for j in range(len(libhook_logs_glibc)):
            # cursors for locating logs
            glibc_cursor = 0
            ffmalloc_cursor = 0

            # calculate reserver memory and used memory
            glibc_log = libhook_logs_glibc[j]
            typ0, args0, ret0, syslib0 = libeval.parse_log(libhook_logs_glibc[j])

            # flag indicating if one glibc log can be found in ffmalloc log
            found_flag = 0

            for ffmalloc_log in libhook_logs_ffmalloc:
                typ1, args1, ret1, syslib1 = libeval.parse_log(ffmalloc_log)
                if typ0 == 'malloc' or typ0 == 'valloc':
                    if typ0 == typ1 and args0[0] == args1[0]:
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                if typ0 == typ1 == 'free':
                    if args0[0] == args1[0] and args0[0] == 'NULL':
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                    # trace the freed memory
                    else:
                        if args1[0] == 'NULL':
                            pass
                        try:
                            if libeval.closest_index(glibc_free_dict[args0[0]], glibc_lib2all[glibc_log]) == libeval.closest_index(ffmalloc_free_dict[args1[0]], ffmalloc_lib2all[ffmalloc_log]):
                                glibc_cursor = libeval.search_log(
                                    glibc_lib2all, glibc_log)
                                ffmalloc_cursor = libeval.search_log(
                                    ffmalloc_lib2all, ffmalloc_log)
                                aligned_ffmalloc_logs.append(ffmalloc_log)
                                libhook_logs_ffmalloc.remove(ffmalloc_log)
                                found_flag = 1
                                break
                        except Exception as e:
                            # print(e)
                            pass
                if typ0 == 'realloc' or typ0 == 'mmap':
                    if typ0 == typ1 and args0[1] == args1[1]:
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                if typ0 == 'memalign' or typ0 == 'calloc':
                    if typ0 == typ1 and args0 == args1:
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                if typ0 == 'posix_memalign' or typ0 == 'reallocarray':
                    if typ0 == typ1 and args0[1] == args1[1] and args0[2] == args1[2]:
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                if typ0 == 'munmap' and typ0 == typ1:
                    # trace the unmapped memory
                    if libeval.closest_index(glibc_munmap_dict[args0[0]], glibc_lib2all[glibc_log]) == libeval.closest_index(ffmalloc_munmap_dict[args1[0]], ffmalloc_lib2all[ffmalloc_log]):
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break
                if typ0 == 'sbrk' and typ0 == typ1:
                    if args0 == args1:
                        glibc_cursor = libeval.search_log(glibc_lib2all, glibc_log)
                        ffmalloc_cursor = libeval.search_log(
                            ffmalloc_lib2all, ffmalloc_log)
                        aligned_ffmalloc_logs.append(ffmalloc_log)
                        libhook_logs_ffmalloc.remove(ffmalloc_log)
                        found_flag = 1
                        break


            glibc_cursor = libeval.update_item(
                glibc_cursor, libeval.search_log(glibc_lib2all, glibc_log))
            ffmalloc_cursor = libeval.update_item(
                ffmalloc_cursor, libeval.search_log(ffmalloc_lib2all, ffmalloc_log))

            if found_flag == 1:
                reserved_memory_glibc_total = glibc_result[glibc_cursor]
                reserved_memory_ffmalloc_total = ffmalloc_result[ffmalloc_cursor]
                if reserved_memory_glibc_total == 0:
                    diff_reserved = 1
                if reserved_memory_glibc_total != 0:
                    diff_reserved = reserved_memory_ffmalloc_total/reserved_memory_glibc_total
                print("g_line: %s, ff_line: %s, g_rsv: %d, ff_rsv: %d, ff_rsv/g_rsv: %.2f" % (glibc_cursor+1,
                      ffmalloc_cursor+1, glibc_result[glibc_cursor], ffmalloc_result[ffmalloc_cursor], diff_reserved))
                # ax[i].plot(valid_result_index, diff_reserved, c="red")  
                valid_result_index = valid_result_index + 1  
                # diff_yaxis.append(diff_reserved)
            elif found_flag == 0:
                print('NOT ALIGNED: g_line: %d %s' % (libeval.search_log(glibc_lib2all, glibc_log)+1, glibc_log), end='')
            else:
                pass

    #         #draw figure
    #         # ax[i].plot(range(len(diff_yaxis)), diff_yaxis, c="red")
    #         # ax[i].plot(range(glibc_cursor), diffs_used, c="green")
    #         ax[i].axhline(y=1, xmin=0, xmax=valid_result_index, color='black', linestyle="dashed")
    #         ax[i].get_xaxis().set_visible(False)
    #         title = format("log/glibc/%s log/ffmalloc/%s" %(files_glibc[i], files_ffmalloc[i]))
    #         ax[i].set_title(title)
    # fig.tight_layout()
    # plt.savefig('eval.pdf')


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
    print(tab + '-r | --run_program')
    print(tab * 2 + 'run the program to generated logs, or will evaluate existed logs')


def main(argv):
    start0 = time.time()
    if not os.path.exists('./log/glibc'):
        os.mkdir('./log/glibc')
    if not os.path.exists('./log/ffmalloc'):
        os.mkdir('./log/ffmalloc')
    libhook_path = '/home/ziyu/research_project/eval-malloc/libhook/libhook.so'
    ffmalloc_path = '/home/ziyu/research_project/ffmalloc/libffmallocnpst.so'
    program = 'ls'
    run_program = None
    try:
        opts, args = getopt.getopt(argv, 'hcnrl:f:p:', [
                                   'help', 'clean', 'non_write', 'run_program', 'libhook_path=', 'ffmalloc_path=', 'program='])
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
        elif opt in ('-r', '--run_program'):
            run_program = True
        elif opt in ('-h', '--help'):
            usage()
            sys.exit(0)
    if libhook_path is None or ffmalloc_path is None:
        usage()
        sys.exit(1)
    if not os.path.exists(libhook_path):
        print('wrong libhook path: %s' % libhook_path)
        sys.exit(1)
    if not os.path.exists(ffmalloc_path):
        print('wrong ffmalloc path: %s' % ffmalloc_path)
        sys.exit(1)

    if run_program is True:
        os.system('LD_PRELOAD={} strace -e trace=mmap,munmap,brk -f -ff -o ./log/glibc/strace -ttt {} 2>./log/glibc/hook.log'.format(libhook_path, program))
        os.system('LD_PRELOAD=\'{} {}\' strace -e trace=mmap,munmap,brk -f -ff -o ./log/ffmalloc/strace -ttt {} 2>./log/ffmalloc/hook.log'.format(libhook_path, ffmalloc_path, program))    
        logs_pre_glibc = libeval.PreLog('./log/glibc', pids)
        logs_pre_glibc.pre_processing()
        logs_pre_ffmalloc = libeval.PreLog('./log/ffmalloc', pids)
        logs_pre_ffmalloc.pre_processing()
        eval_reserved_memory()
    # logs_pre_glibc = libeval.PreLog('./log/glibc', pids)
    # logs_pre_glibc.pre_processing()
    logs_pre_ffmalloc = libeval.PreLog('./log/ffmalloc', pids)
    logs_pre_ffmalloc.pre_processing()
    eval_reserved_memory()

    end0 = time.time()
    print("time used: %.2f seconds" %(end0-start0))


if __name__ == '__main__':
    main(sys.argv[1:])
