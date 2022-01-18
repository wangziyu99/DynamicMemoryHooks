#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <malloc.h>
#include <sys/mman.h>

#define MAX 3
pthread_t thread[2];
pthread_mutex_t mut;
int number = 0, i;

void *thread1() {
    printf("thread1_tid = %ld\n", syscall(SYS_gettid));
    void *p1 = malloc(10000);
    void *test1 = mmap(0, 20, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
    -1, 0);
    void *test2 = mmap(0, 20, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
    -1, 0);
    munmap(test2, 1000);
    void *p2 = calloc(10, 10);
    for (i = 0; i < MAX; i++) {
        printf("thread1 : number = %d\n", number);
        pthread_mutex_lock(&mut);
        number += 100;
        p1 = realloc(p1, number);
        void *p12 = valloc(1000);
        void *p13 = memalign(10, 200);
        int flag = posix_memalign(p13, 8, 120);
        pthread_mutex_unlock(&mut);
        sleep(2);
    }
    free(p1);
    pthread_exit(NULL);
}

void *thread2() {
    printf("thread2_tid = %ld\n", syscall(SYS_gettid));
    void *p2 = malloc(100);
    void *p3 = calloc(10, 10);
    for (i = 0; i < MAX; i++) {
        printf("thread2 : number = %d\n", number);
        pthread_mutex_lock(&mut);
        number += 100;
        p2 = realloc(p2, number);
        pthread_mutex_unlock(&mut);
        sleep(1);
    }
    pthread_exit(NULL);
}

void thread_create(void) {
    int temp;
    memset(&thread, 0, sizeof(thread));
    /*create threads*/
    if ((temp = pthread_create(&thread[0], NULL, thread1, NULL)) != 0)
        printf("thread1 failed\n");
    else
        printf("thread1 created\n");
    if ((temp = pthread_create(&thread[1], NULL, thread2, NULL)) != 0)
        printf("thread2 failed");
    else
        printf("thread2 created\n");
}

void thread_wait(void) {
    /*waiting for thread ending*/
    if (thread[0] != 0) {                   //comment4
        pthread_join(thread[0], NULL);
        printf("thread1 end\n");
    }
    if (thread[1] != 0) {                //comment5
        pthread_join(thread[1], NULL);
        printf("thread2 end\n");
    }
}

int main() {
    /*initialize mutex lock*/
    printf("parent_pid = %d\n", getpid());
    pthread_mutex_init(&mut, NULL);
    thread_create();
    thread_wait();
    printf("happy ending\n");
    return 0;
}
