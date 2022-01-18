all: libhook.so pttest

libhook.so: libhook.c
	gcc -g -Wall -shared -fPIC -o libhook.so libhook.c -ldl -fno-stack-protector -g

pttest: pttest.c
	gcc -g pttest.c -o pttest -lpthread -rdynamic -g

strace: pttest libhook.so
	LD_PRELOAD=./libhook.so strace -e trace=mmap,munmap,brk -f -ff -o ./log/strace -ttt ./pttest 2>./log/hook.log

test: pttest libhook.so
	LD_PRELOAD=./libhook.so ./pttest 2>./log/hook.log

clean:
	rm -f pttest libhook.so out.* *.log ./log/*.log ./log/strace.* strace.* ./fig/*.png *.avi *.pdf
