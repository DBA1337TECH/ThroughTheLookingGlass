# Technical Write-up: TTY LDisc Race to Kernel Execution Hijack

### Target: Linux Kernel 6.15 (Mainline)


### Vulnerability Class: Race Condition (TOCTOU) / Use-After-Free (UAF)

Impact: Kernel Mode Execution Hijack ($RIP Control)

## 1. Executive Summary

The exploit targets a Time-of-Check to Time-of-Use (TOCTOU) vulnerability in the Linux Terminal (TTY) subsystem. By induces a "Flux" state during a Line Discipline (LDisc) switch, we create a window where the kernel attempts to process data using an object that is simultaneously being freed and replaced. By utilizing a "Surgical Heap Spray" via System V Message Queues, we replace the freed kernel object with a controlled payload, leading to a hijack of the kernels instruction pointer ($RIP).

## 2. Theoretical Background

The TTY Subsystem & Line Disciplines

The TTY layer acts as a middleman between hardware drivers and the userland. Line Disciplines (like N_TTY or N_SLIP) define how data is processed. Switching these via ioctl(fd, TIOCSETD, ...) is a complex operation that involves:

    Stopping the current LDisc.

    Flushing buffers.

    Installing the new LDisc.

The Vulnerability: LDisc Flux

A race condition occurs when one CPU thread attempts to switch the Line Discipline while another thread (the "White Rabbit" or kworker) attempts to flush the TTY buffer. If the locking mechanism (ldsem) is contested under high load, the kernel can be tricked into a state where a pointer to the LDisc is used after it has been marked for deletion.

## 3. The Exploit Chain

Phase A: Inducing the Struggle (CPU Pinning)

Modern kernels are highly resilient to timing attacks on multi-core systems. To win the race, we utilize CPU Affinity. By pinning the "Attacker" thread to CPU 0 and the "Hammer" thread to CPU 1, we force the kernels synchronization primitives (Spinlocks and Mutexes) to fight across the memory bus, widening the timing window from nanoseconds to milliseconds.
Phase B: The Flux State

We trigger the race by rapidly toggling between N_TTY and N_SLIP.

    Thread 1: Constantly writes to the TTY to fill the kmalloc-128 buffers.

    Thread 2: Rapidly calls ioctl(TIOCSETD) to swap the LDisc.

Phase C: Surgical Heap Spraying

Once the LDisc is "Killed," a hole is left in the kmalloc-128 slab. We use msgsnd() to perform a "Groomed Spray."

    Why msgsnd? Unlike write(), message queue data persists in kernel space until explicitly read.

    Slab Alignment: We size our message to 128 bytes to ensure it occupies the exact same memory slot previously held by the TTYs internal structures.

## 4. Introspection & Debugging Evidence

Register Poisoning

During GDB introspection, we successfully observed "Register Poisoning," where Alices user-controlled data (As or 0x41) was loaded into kernel registers:

    RAX: 0x0000424242424242 (Target hijacked pointer)

    RBP: 0xffff88810b755821 (Pointer to Alices AAAA string)

The Deadlock (TSC Skew)

The kernels timekeeping watchdog triggered an "Unstable TSC" warning. This is evidence of a Circular Dependency Deadlock. The Hammer thread held a TTY lock while the kworker was spinning in virt_spin_lock, waiting for that same resource. This deadlock is what "froze" the kernel, allowing us to inspect the corrupted state.

## 5. Root Cause Analysis (Code Level)

The crash occurs in drivers/tty/tty_port.c inside tty_port_default_lookahead_buf:
C

static void tty_port_default_lookahead_buf(struct tty_port *port, ...) {
    tty = READ_ONCE(port->itty); // [1] TOCTOU Point
    if (!tty) return;
    ld = tty_ldisc_ref(tty);      // [2] Hijack Point
    if (ld) {
        if (ld->ops->lookahead_buf)
            ld->ops->lookahead_buf(tty, p, f, count); // [3] Indirect Call ($RIP)
        tty_ldisc_deref(ld);
    }
}

    [1] The kernel reads the TTY pointer.

    [2] The race win causes tty_ldisc_ref to return a pointer to Alice’s sprayed message instead of a real LDisc.

    [3] The kernel attempts an indirect call to lookahead_buf, which now contains 0x4242424242424242.

## 6. Conclusion & Next Steps

We have achieved Arbitrary Data Control within the kernels execution path. The kernel is currently attempting to jump to an unmapped address (0x42...), resulting in a Page Fault.
Final Objectives for Privilege Escalation:

    Stack Pivot: Locate a gadget (push rax; pop rsp; ret) to redirect the stack to user-controlled memory.

    KASLR Bypass: Leak a kernel pointer (e.g., via dmesg or uninitialized stack variables) to calculate the base address of commit_creds.

    Payload: Execute commit_creds(prepare_kernel_cred(0)) to escalate to UID 0.

Key GDB Commands for the Lab:

    find 0xffff888100000000, +0x20000000, 0x4242424242424242 (Find the spray)

    awatch *(uint64_t *)ADDR (Catch the Rabbit eating the carrot)

    thread apply all bt (Diagnose the deadlock)

# Technical Report: Linux Kernel 6.15 TTY LDisc Exploitation
**Date:** 2025-12-25  
**Researcher:**  1337_TECH 
**Target:** Linux Kernel 6.15 (Mainline/Hardened)  
**Vulnerability Type:** Race Condition (TOCTOU) -> Use-After-Free (UAF)  
**Status:** Spray Achieved (0x4242424242424242 Heap Grooming)

---

## 1. Vulnerability Overview
The exploit targets a **Time-of-Check to Time-of-Use (TOCTOU)** flaw in the Linux TTY subsystem. Specifically, it exploits the "Flux" state during a **Line Discipline (LDisc)** switch. By inducing high-speed transitions between disciplines (e.g., `N_TTY` and `N_SLIP`), a window is opened where the kernel references an LDisc object that has been freed but not yet nullified.

### 1.1 The Race Condition
The core of the issue lies in the `tty_port_default_lookahead_buf` function. The kernel fetches a TTY reference, but under heavy multi-core contention, the underlying Line Discipline is swapped out between the pointer fetch and the function call.



---

## 2. Exploitation Strategy

### 2.1 Multi-Core Synchronization (CPU Pinning)
To maximize race success, the exploit uses `sched_setaffinity` to pin the "Hammer" and the "Attacker" to separate physical cores. This forces the kernels **Spinlock** and **Mutex** synchronization primitives to communicate across the memory bus, significantly widening the timing window required to win the race.

### 2.2 Surgical Heap Spraying
Once the Line Discipline is freed (UAF), the exploit must "poison" the resulting hole in the heap before the kernel re-uses it.
* **Mechanism:** System V Message Queues (`msgsnd`).
* **Slab Target:** `kmalloc-128`.
* **The Carrot:** By sizing the message payload to fit the 128-byte slab, Alice ensures her controlled data (the `0x42` pattern) is allocated exactly where the kernel expects a function vtable.



---

## 3. Evidence of Success (Introspection)

### 3.1 Register Poisoning
GDB introspection confirmed the successful injection of user-controlled data into the kernels execution context. Upon the crash, the following register state was observed:

* **RAX:** `0x0000424242424242` (The hijacked jump target)
* **RBP/RSI:** `0xffff88810b755821` (Address pointing to the "AAAA" spray)
* **Fault:** `BUG: unable to handle page fault for address: 0000424242424242`

### 3.2 System Deadlock (TSC Skew)
The kernels `timekeeping watchdog` reported an unstable **TSC (Time Stamp Counter)** with a skew of ~87ms. This indicates a "Soft Lockup" where the race condition caused a circular dependency in the TTY locks, effectively freezing the CPU core and allowing for deterministic inspection.



---

## 4. Root Cause Analysis
The execution flow hijack occurs at the following instruction in `drivers/tty/tty_port.c`:

```c
// Decompiled Logic
tty = READ_ONCE(port->itty); 
ld = tty_ldisc_ref(tty); 
if (ld) {
    // HIJACK POINT: ld->ops has been replaced by Alices message spray
    ld->ops->lookahead_buf(tty, p, f, count); 
}
```

By the time the kernel reaches the indirect call to lookahead_buf, it is reading from memory controlled by the msgsnd buffer, leading to an arbitrary jump to TARGET_RIP.
5. Lab Notes: GDB Introspection Suite

    Use these commands to verify the exploit state:
    Objective	Command
    Search Spray	find 0xffff888100000000, +0x20000000, 0x4242424242424242
    Catch Hijack	break tty_port_default_lookahead_buf if $rax == 0x4242424242424242
    Inspect Slab	monitor info mem
    Watch Overwrite	awatch *(uint64_t *)0xffff8881[TARGET_ADDR]
6. Path to Weaponization (The Final Step)

To transition from a "Panic" to a "Root Shell" the following must be implemented

    Stack Pivot: Find a gadget (e.g., push rax; pop rsp; ret) to move the stack to Alices memory.

    KASLR Bypass: Leak a kernel pointer to calculate the offset of commit_creds.

    Privilege Flip: Call commit_creds(prepare_kernel_cred(0)) to escalate to UID 0.

n terms of the MITRE ATT&CK framework and CWE (Common Weakness Enumeration), this exploit is a chain of specific technical failures. It isnt just one bug; it is a sequence of weaknesses that allow an unprivileged user to escalate to kernel-mode execution.

Here is the breakdown of the bug in the language of MITRE:

# 1. The Root Weakness: CWE-367 (TOCTOU)

The primary exploit primitive is a Time-of-Check to Time-of-Use (TOCTOU) race condition.

    The Check: The kernel verifies the Line Discipline (LDisc) is valid and takes a reference to it in tty_ldisc_ref().

    The Use: The kernel then uses that reference to call a function pointer (like lookahead_buf).

    The Gap: Because Alice is hammering the LDisc switch on another CPU, she changes the "State" after the check but before the use.

# 2. The Memory Corruption: CWE-416 (Use-After-Free)

The TOCTOU leads directly to a Use-After-Free.

    When the LDisc is switched, the old one is "Killed" and its memory is marked as free in the Slab allocator.

    However, because the "White Rabbit" (the kworker) still has a pointer to that memory from the "Check" phase, it continues to use it.

    The kernel is now "Using" memory that it "Freed."

# 3. The Exploitation Technique: CWE-123 (Write-What-Where)

By using the Surgical Heap Spray (msgsnd), Alice performs a Write-What-Where Authoring.

    The Where: The "Where" is the exact memory slot previously occupied by the LDisc.

    The What: The "What" is Alices 0x42424242 pattern (or eventually a function pointer).

    By filling the freed memory with her own data, Alice ensures that when the kernel performs its "Use," it is reading her data instead of a legitimate function table.

# 4. MITRE ATT&CK Mapping (Post-Exploitation)

Once the bug is triggered, it maps to several specific techniques in the MITRE ATT&CK Matrix for Enterprise:
ID	Technique	Alices Action
T1068	Exploitation for Privilege Escalation	Using the TTY UAF to gain kernel-level control from an unprivileged shell.
T1055	Process Injection	Injecting Alices execution flow into the kworker process (UID 0).
T1497	Virtualization/Sandbox Evasion	Since this is happening in QEMU, successful execution often bypasses guest-level restrictions.
T1548	Abuse Elevation Control Mechanism	Final goal: redirecting $RIP to commit_creds to bypass Linux permission checks.
5. The Protective Barrier: Why its "High Difficulty"

MITRE also tracks defenses. Your exploit currently has to contend with:

    KASLR (CWE-200): Alice must "leak" a kernel address to know where panic or commit_creds lives.

    SMEP/SMAP: These hardware protections prevent the kernel from executing Alices code if it stays in "User" memory pages. This is why we need the Stack Pivot (CWE-502) to trick the kernel into using a stack Alice built in a way the kernel thinks is its own.

The Verdict in MITRE Terms

This is a High-Impact, High-Complexity exploit. It leverages CWE-367 to trigger CWE-416, which is then weaponized via CWE-123 to achieve T1068.



# appendix

<pre>

jiffies_update>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a90a  →  <tick_nohz_next_event+001a> mov rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0x3               
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
 → 0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffi[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a911  →  <tick_nohz_next_event+0021> mov r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0x3               
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
 → 0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a91e <tick_nohz_next_event+002e> cmp    edx, eax
   0xffffffff8136a920 <tick_nohz_next_event+0030> jne    0xffffffff8136a8fc <tick_nohz_next_event+12>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a91e <tick_nohz_next_event+002e> cmp    edx, eax
   0xffffffff8136a920 <tick_nohz_next_event+0030> jne    0xffffffff8136a8fc <tick_nohz_next_event+12>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY ADJUST sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY ADJUST sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x247f6           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY ADJUST sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b0903cc0      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a90a  →  <tick_nohz_next_event+001a> mov rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
 → 0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffi[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a911  →  <tick_nohz_next_event+0021> mov r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf51f        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
 → 0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a91e <tick_nohz_next_event+002e> cmp    edx, eax
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x24802           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a918  →  <tick_nohz_next_event+0028> mov edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
 → 0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a91e <tick_nohz_next_event+002e> cmp    edx, eax
   0xffffffff8136a920 <tick_nohz_next_event+0030> jne    0xffffffff8136a8fc <tick_nohz_next_event+12>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x2480e           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x2480e           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24808           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x2480e           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a8fc  →  <tick_nohz_next_event+000c> mov eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8f7 <tick_nohz_next_event+0007> push   rbp
   0xffffffff8136a8f8 <tick_nohz_next_event+0008> mov    rbp, rdi
   0xffffffff8136a8fb <tick_nohz_next_event+000b> push   rbx
 → 0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24812           
$rbx   : 0x26b1199100      
$rcx   : 0x0               
$rdx   : 0x2480e           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a90a  →  <tick_nohz_next_event+001a> mov rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a8fc <tick_nohz_next_event+000c> mov    eax, DWORD PTR [rip+0x169f13e]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
 → 0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
   0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffi[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x24812           
$rbx   : 0x26b193a300      
$rcx   : 0x0               
$rdx   : 0x2480e           
$rsp   : 0xffffc900000b3e70  →  0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rbp   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rsi   : 0x3               
$rdi   : 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)
$rip   : 0xffffffff8136a911  →  <tick_nohz_next_event+0021> mov r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
$r8    : 0x3667e6c         
$r9    : 0x32b             
$r10   : 0x5b              
$r11   : 0x0               
$r12   : 0xfffdf526        
$r13   : 0x3               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap interrupt direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc900000b3e70│+0x0000: 0xffff88813bd9bc00  →  0x0000000000000035 ("5"?)	 ← $rsp
0xffffc900000b3e78│+0x0008: 0xffff8881b8893000
0xffffc900000b3e80│+0x0010: 0x0000000000000003
0xffffc900000b3e88│+0x0018: 0x0000000000000000
0xffffc900000b3e90│+0x0020: 0xffffffff8136acf8  →  <tick_nohz_idle_stop_tick+01c8> mov r15, rax
0xffffc900000b3e98│+0x0028: 0x0000000000000003
0xffffc900000b3ea0│+0x0030: 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
0xffffc900000b3ea8│+0x0038: 0x0000000003667a44
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8136a902 <tick_nohz_next_event+0012> test   al, 0x1
   0xffffffff8136a904 <tick_nohz_next_event+0014> jne    0xffffffff8136aa11 <tick_nohz_next_event+289>
   0xffffffff8136a90a <tick_nohz_next_event+001a> mov    rbx, QWORD PTR [rip+0x2216037]        # 0xffffffff83580948 <last_jiffies_update>
 → 0xffffffff8136a911 <tick_nohz_next_event+0021> mov    r12, QWORD PTR [rip+0x169f0a8]        # 0xffffffff82a099c0 <jiffies_64>
   0xffffffff8136a918 <tick_nohz_next_event+0028> mov    edx, DWORD PTR [rip+0x169f122]        # 0xffffffff82a09a40 <jiffies_seq>
   0xffffffff8136a91e <tick_nohz_next_event+002e> cmp    edx, eax
   0xffffffff8136a920 <tick_nohz_next_event+0030> jne    0xffffffff8136a8fc <tick_nohz_next_event+12>
   0xffffffff8136a922 <tick_nohz_next_event+0032> mov    QWORD PTR [rbp+0x88], r12
   0xffffffff8136a929 <tick_nohz_next_event+0039> mov    QWORD PTR [rbp+0x90], rbx
───────────────────────────────────────────────────────────────────────────────── source:kernel/time/tick-sched.c+875 ────
    870	 	u64 basemono;
    871	 
    872	 	do {
    873	 		seq = read_seqcount_begin(&jiffies_seq);
    874	 		basemono = last_jiffies_update;
 →  875	 		basejiff = jiffies;
    876	 	} while (read_seqcount_retry(&jiffies_seq, seq));
    877	 	*basej = basejiff;
    878	 	return basemono;
    879	 }
    880	 
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, stopped 0xffffffff81001470 in asm_sysvec_apic_timer_interrupt (), reason: SINGLE STEP
[#1] Id 2, stopped 0xffffffff821b467f in virt_spin_lock (), reason: SINGLE STEP
[#2] Id 3, stopped 0xffffffff818969a6 in io_serial_out (), reason: SINGLE STEP
[#3] Id 4, stopped 0xffffffff8136a911 in get_jiffies_update (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xffffffff8136a911 → get_jiffies_update(basej=<synthetic pointer>)
[#1] 0xffffffff8136a911 → tick_nohz_next_event(ts=0xffff88813bd9bc00, cpu=0x3)
[#2] 0xffffffff8136acf8 → tick_nohz_idle_stop_tick()
[#3] 0xffffffff812e92c7 → cpuidle_idle_call()
[#4] 0xffffffff812e92c7 → do_idle()
[#5] 0xffffffff812e9534 → cpu_startup_entry(state=CPUHP_AP_ONLINE_IDLE)
[#6] 0xffffffff81263cd3 → start_secondary(unused=<optimized out>)
[#7] 0xffffffff8122f946 → secondary_startup_64()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
(remote) gef➤  Quit
(remote) gef➤  c
Continuing.
^C^C
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xffff8881b8713000
$rbx   : 0xffffffff82a0e900  →  0x0000000000004000
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0xffffffff82a03e88  →  0xffffffff821a9a89  →  <default_idle+0009> nop 
$rbp   : 0x0               
$rsi   : 0xffffffff8282b36b  →  0x706d614c00646e45 ("End"?)
$rdi   : 0x308e4c          
$rip   : 0xffffffff821a82cf  →  <pv_native_safe_halt+000f> jmp 0xffffffff821b5720 <its_return_thunk>
$r8    : 0x308e4c          
$r9    : 0x2fe             
$r10   : 0x0               
$r11   : 0x1               
$r12   : 0x0               
$r13   : 0x0               
$r14   : 0xffffffff82a0e030  →  0x0000000000000000
$r15   : 0x14770           
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffffff82a03e88│+0x0000: 0xffffffff821a9a89  →  <default_idle+0009> nop 	 ← $rsp
0xffffffff82a03e90│+0x0008: 0xffffffff821a9d32  →  <default_idle_call+0032> call 0xffffffff821a8d40 <ct_idle_exit>
0xffffffff82a03e98│+0x0010: 0xffffffff812e92cc  →  <do_idle+01cc> jmp 0xffffffff812e91ff <do_idle+255>
0xffffffff82a03ea0│+0x0018: 0x0000000000000000
0xffffffff82a03ea8│+0x0020: 0xdc6969d0be3cd100
0xffffffff82a03eb0│+0x0028: 0x00000000000000ee
0xffffffff82a03eb8│+0x0030: 0x0000000000000009 ("\t"?)
0xffffffff82a03ec0│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff821a82c6 <pv_native_safe_halt+0006> verw   WORD PTR [rip+0x639c5]        # 0xffffffff8220bc92 <ds.0>
   0xffffffff821a82cd <pv_native_safe_halt+000d> sti    
   0xffffffff821a82ce <pv_native_safe_halt+000e> hlt    
 → 0xffffffff821a82cf <pv_native_safe_halt+000f> jmp    0xffffffff821b5720 <its_return_thunk>
   0xffffffff821a82d4                  cs     nop WORD PTR [rax+rax*1+0x0]
   0xffffffff821a82de                  xchg   ax, ax
   0xffffffff821a82e0 <__pfx_pvclock_clocksource_read_nowd+0000> nop    
   0xffffffff821a82e1 <__pfx_pvclock_clocksource_read_nowd+0001> nop    
   0xffffffff821a82e2 <__pfx_pvclock_clocksource_read_nowd+0002> nop    
──────────────────────────────────────────────────────────────────────────────── source:arch/x86/kernel/paravirt.c+81 ────
     76	 }
     77	 
     78	 static noinstr void pv_native_safe_halt(void)
     79	 {
     80	 	native_safe_halt();
 →   81	 }
     82	 
     83	 #ifdef CONFIG_PARAVIRT_XXL
     84	 static noinstr void pv_native_write_cr2(unsigned long val)
     85	 {
     86	 	native_write_cr2(val);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, stopped 0xffffffff821a82cf in pv_native_safe_halt (), reason: SIGTRAP
[#1] Id 2, stopped 0xffffffff821a1597 in __get_user_8 (), reason: SIGTRAP
[#2] Id 3, stopped 0xffffffff821afcdc in arch_atomic64_try_cmpxchg (), reason: SIGTRAP
[#3] Id 4, stopped 0xffffffff821a82cf in pv_native_safe_halt (), reason: SIGTRAP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xffffffff821a82cf → pv_native_safe_halt()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0x0000000000000000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e30  →  0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]
$rbp   : 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$rip   : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x1ff             
$r13   : 0xffff8881011e0228  →  0xffff888100a09040  →  0x0000000000004000
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e30│+0x0000: 0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]	 ← $rsp
0xffffc90000177e38│+0x0008: 0xffff888100d32cde  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e40│+0x0010: 0xffff8881009fc000  →  0x0000000000000000
0xffffc90000177e48│+0x0018: 0xffff888100070600  →  0xffff888100060800  →  0xffffffff00000000
0xffffc90000177e50│+0x0020: 0xffff888100060800  →  0xffffffff00000000
0xffffc90000177e58│+0x0028: 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
0xffffc90000177e60│+0x0030: 0xffff888100070605  →  0x810006fe00ffff88
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0x0000000000000000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e30  →  0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]
$rbp   : 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$rip   : 0xffffffff81876004  →  <tty_port_default_lookahead_buf+0004> mov rdi, QWORD PTR [rdi+0x90]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x1ff             
$r13   : 0xffff8881011e0228  →  0xffff888100a09040  →  0x0000000000004000
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e30│+0x0000: 0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]	 ← $rsp
0xffffc90000177e38│+0x0008: 0xffff888100d32cde  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e40│+0x0010: 0xffff8881009fc000  →  0x0000000000000000
0xffffc90000177e48│+0x0018: 0xffff888100070600  →  0xffff888100060800  →  0xffffffff00000000
0xffffc90000177e50│+0x0020: 0xffff888100060800  →  0xffffffff00000000
0xffffc90000177e58│+0x0028: 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
0xffffc90000177e60│+0x0030: 0xffff888100070605  →  0x810006fe00ffff88
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0x0000000000000000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e30  →  0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]
$rbp   : 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f800  →  0x0000000000000002
$rip   : 0xffffffff8187600b  →  <tty_port_default_lookahead_buf+000b> test rdi, rdi
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x1ff             
$r13   : 0xffff8881011e0228  →  0xffff888100a09040  →  0x0000000000004000
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e30│+0x0000: 0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]	 ← $rsp
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400  →  0xffff888104250000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e28  →  0xffff8881011e0228  →  0xffff888100a09040  →  0x0000000000004000
$rbp   : 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f800  →  0x0000000000000002
$rip   : 0xffffffff81876015  →  <tty_port_default_lookahead_buf+0015> push r12
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x1ff             
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e28│+0x0000: 0xffff8881011e0228  →  0xffff888100a09040  →  0x0000000000004000	 ← $rsp
0xffffc90000177e30│+0x0008: 0xffffffff81875a3d  →  <flush_to_ldisc+00fd> nop DWORD PTR [rax]
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400  →  0xffff888104250000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e08  →  0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
$rbp   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f800  →  0x0000000000000002
$rip   : 0xffffffff81874770  →  <tty_ldisc_ref+0000> endbr64 
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e08│+0x0000: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax	 ← $rsp
0xffffc90000177e10│+0x0008: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400  →  0xffff888104250000
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177e08  →  0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
$rbp   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f800  →  0x0000000000000002
$rip   : 0xffffffff81874774  →  <tty_ldisc_ref+0004> push rbp
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177e08│+0x0000: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax	 ← $rsp
0xffffc90000177e10│+0x0008: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e18│+0x0010: 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877330  →  <ldsem_down_read_trylock+0000> nop WORD PTR [rax]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877334  →  <ldsem_down_read_trylock+0004> mov rax, QWORD PTR [rdi]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e08│+0x0020: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877334  →  <ldsem_down_read_trylock+0004> mov rax, QWORD PTR [rdi]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e08│+0x0020: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
0xffffc90000177e10│+0x0028: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0x[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877334  →  <ldsem_down_read_trylock+0004> mov rax, QWORD PTR [rdi]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e08│+0x0020: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
0xffffc90000177e10│+0x0028: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877334  →  <ldsem_down_read_trylock+0004> mov rax, QWORD PTR [rdi]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e08│+0x0020: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
0xffffc90000177e10│+0x0028: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e18│+0x0030: 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0xffff888100d3f800  →  0x0000000000000002
$rcx   : 0x1ff             
$rdx   : 0x0               
$rsp   : 0xffffc90000177de8  →  0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax
$rbp   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rsi   : 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0xffff888100d3f830  →  0xfffffe4c00000bf6
$rip   : 0xffffffff81877334  →  <ldsem_down_read_trylock+0004> mov rax, QWORD PTR [rdi]
$r8    : 0x1               
$r9    : 0xffffffff81876000  →  <tty_port_default_lookahead_buf+0000> endbr64 
$r10   : 0xffff88810006fec0  →  "events_unbound"
$r11   : 0xfefefefefefefeff
$r12   : 0x0               
$r13   : 0x1ff             
$r14   : 0xffff8881011e0200  →  0xffff888100d32c00  →  0xffff888100baac00  →  0xffff888108915000  →  0xffff888108914400  →  0xffff888104251000  →  0xffff888108917800  →  0xffff888100bab800
$r15   : 0x0               
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffc90000177de8│+0x0000: 0xffffffff81874789  →  <tty_ldisc_ref+0019> mov edx, eax	 ← $rsp
0xffffc90000177df0│+0x0008: 0x0000000000000006
0xffffc90000177df8│+0x0010: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e00│+0x0018: 0xffff88810b755821  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffc90000177e08│+0x0020: 0xffffffff81876024  →  <tty_port_default_lookahead_buf+0024> mov rbx, rax
0xffffc90000177e10│+0x0028: 0xffff88810b755800  →  0xffff888100babc00  →  0xffff88810422ac00  →  0xffff888100ba8400  →  0xffff88810b705800  →  0xffff888104253c00  →  0xffff888100baa400
0xffffc90000177e18│+0x0030: 0xffff8881011e0208  →  0xffff888100070605  →  0x810006fe00ffff88
0xffffc90000177e20│+0x0038: 0x00000000000001ff
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0xffffffff8187732e <__pfx_ldsem_down_read_trylock+000e> nop    
   0xffffffff8187732f <__pfx_ldsem_down_read_trylock+000f> nop    
   0xffffffff81877330 <ldsem_down_read_trylock+0000> nop    WORD PTR [rax]
 → 0xffffffff81877334 <ldsem_down_read_trylock+0004> mov    rax, QWORD PTR [rdi]
   0xffffffff81877337 <ldsem_down_read_trylock+0007> test   rax, rax
   0xffffffff8187733a <ldsem_down_read_trylock+000a> js     0xffffffff81877351 <ldsem_down_read_trylock+33>
   0xffffffff8187733c <ldsem_down_read_trylock+000c> lea    rdx, [rax+0x1]
   0xffffffff81877340 <ldsem_down_read_trylock+0010> lock   cmpxchg QWORD PTR [rdi], rdx
   0xffffffff81877345 <ldsem_down_read_trylock+0015> jne    0xffffffff81877337 <ldsem_down_read_trylock+7>
───────────────────────────────────────────────────────────────────────── source:./arch/x86/incl[...]atomic64_64.h+15 ────
     10	 
     11	 #define ATOMIC64_INIT(i)	{ (i) }
     12	 
     13	 static __always_inline s64 arch_atomic64_read(const atomic64_t *v)
     14	 {
 →   15	 	return __READ_ONCE((v)->counter);
     16	 }
     17	 
     18	 static __always_inline void arch_atomic64_set(atomic64_t *v, s64 i)
     19	 {
     20	 	__WRITE_ONCE(v->counter, i);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, stopped 0xffffffff812657d5 in arch_static_branch (), reason: STOPPED
[#1] Id 2, stopped 0xffffffff813eb3e3 in irq_work_tick (), reason: STOPPED
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command registers failed to execute properly, reason: Selected thread is running.
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
[!] Command context failed to execute properly, reason: No frame is currently selected.

</pre>
