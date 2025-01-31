# dlopen() shellcode
# - Calls dlopen() on our library filepath
# - Signature:  void shellcode(void* dlopen_fn_ptr, char* lib_path_sz);
#               dlopen_fn_ptr   - RDI
#               lib_path_sz     - RSI

.org 0x0
.global _start

.section .text
    _start:
        movq        %rdi, %r11      # Temporarily remove dlopen_fn_ptr

        # Set up dlopen() call
        movq        %rsi, %rdi      # Move path string ready for dlopen()
        movq        $2, %rsi        # RTLD_NOW
        call        *%r11

        # Check if dlopen() returned NULL
        cmpq        $0, %rax
        jz          set_sigusr2

        # Prepare kill() syscall
    set_sigusr1:
        movq        $10, %rsi       # SIGUSR1 = 10
        jmp         signal_injector
    set_sigusr2:
        movq        $12, %rsi       # SIGUSR2 = 12
    signal_injector:
        movq        $62, %rax       # kill() syscall
        movq        $0, %rdi        # PID, dummy value - the kill() syscall
        syscall                     # is replaced with munmap() anyway
