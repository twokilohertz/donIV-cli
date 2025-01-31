#include "inject.hpp"
#include "process.hpp"
#include "ptrace.hpp"
#include "syscalls.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <sys/ptrace.h>
#include <system_error>
#include <variant>
#include <vector>

extern "C"
{
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

#include <linux/ptrace.h> // Must be included after <sys/ptrace.h>
}

#include "dlopen_shellcode.hpp"

using namespace std::string_view_literals;

static constexpr const std::string_view            LIBC_SO_NAME          = "libc.so.6"sv;
static constexpr const char                        DLOPEN_SYMBOL_NAME[7] = "dlopen";
static constexpr const std::array<std::uint8_t, 2> SYSCALL_ENCODING {0x0f, 0x05};

std::optional<void*> resolve_remote_dlopen(const process& process, std::uintptr_t libc_base_addr) {
    void* ret = nullptr;

    std::array<char, EI_NIDENT> ident_buf {};
    auto maybe_read = process.read_memory(reinterpret_cast<void*>(libc_base_addr), ident_buf.data(), ident_buf.size());
    if (!maybe_read.has_value()) {
        std::println(stderr,
                     "[inject] Failed to read e_ident from target libc: {} ({})",
                     maybe_read.error().message(),
                     maybe_read.error().value());
        return std::nullopt;
    }

    if (std::memcmp(ident_buf.data(), ELFMAG, SELFMAG) != 0) {
        std::println(stderr, "[inject] e_ident did not match");
        std::for_each(ident_buf.cend(), ident_buf.cend(), [](const char c) {
            std::print("> {:#04x}", c);
        });
        return std::nullopt;
    }

    if (ident_buf[4] != ELFCLASS64) {
        std::println(stderr, "[inject] Only supporting ELFCLASS64 for now. Bailing.");
        return std::nullopt;
    }

    Elf64_Ehdr ehdr {};
    maybe_read = process.read_memory(reinterpret_cast<void*>(libc_base_addr), &ehdr, sizeof(ehdr));
    if (!maybe_read.has_value()) {
        std::println(stderr,
                     "[inject] Failed to read ELF header from target libc: {} ({})",
                     maybe_read.error().message(),
                     maybe_read.error().value());
        return std::nullopt;
    }

    if (!ehdr.e_phoff) {
        std::println(stderr, "[inject] Program header offset is null");
        return std::nullopt;
    }

    for (std::uint32_t i = 0; i < ehdr.e_phnum; ++i) {
        Elf64_Phdr phdr {};
        maybe_read = process.read_memory(
            reinterpret_cast<void*>((libc_base_addr + ehdr.e_phoff) + (i * ehdr.e_phentsize)), &phdr, sizeof(phdr));
        if (!maybe_read.has_value()) {
            std::println(stderr,
                         "[inject] Failed to read program header from target libc: {} ({})",
                         maybe_read.error().message(),
                         maybe_read.error().value());
            return std::nullopt;
        }

        if (phdr.p_type != PT_DYNAMIC)
            continue;

        std::uint64_t       str_tab_addr     = 0;
        std::uint64_t       str_tab_size     = 0;
        std::uint64_t       sym_tab_addr     = 0;
        std::uint64_t       sym_tab_ent_size = 0;
        const std::uint64_t dyn_start_addr   = libc_base_addr + phdr.p_vaddr;
        const std::uint64_t dyn_end_addr     = dyn_start_addr + phdr.p_memsz;

        for (std::uint64_t j = dyn_start_addr; j < dyn_end_addr; j += sizeof(Elf64_Dyn)) {
            Elf64_Dyn dyn {};
            maybe_read = process.read_memory(reinterpret_cast<void*>(j), &dyn, sizeof(dyn));
            if (!maybe_read.has_value()) {
                std::println(stderr,
                             "[inject] Failed to read dynamic linking information from target libc: {} ({})",
                             maybe_read.error().message(),
                             maybe_read.error().value());
                return std::nullopt;
            }

            if (dyn.d_tag == DT_STRTAB)
                str_tab_addr = dyn.d_un.d_ptr;
            else if (dyn.d_tag == DT_STRSZ)
                str_tab_size = dyn.d_un.d_val;
            else if (dyn.d_tag == DT_SYMTAB)
                sym_tab_addr = dyn.d_un.d_ptr;
            else if (dyn.d_tag == DT_SYMENT)
                sym_tab_ent_size = dyn.d_un.d_val;
        }

        if (!str_tab_addr || !str_tab_size || !sym_tab_addr || !sym_tab_ent_size) {
            std::println(stderr, "[inject] Failed to find runtime symbol & string table in libc");
            return std::nullopt;
        }

        // Relevant to the cur_addr < str_tab_addr comparison in the loop below
        if (sym_tab_addr >= str_tab_addr) {
            std::println(stderr, "[inject] Just let the developer know 🙄");
            return std::nullopt;
        }

        for (std::uint64_t cur_addr = sym_tab_addr; cur_addr < str_tab_addr; cur_addr += sizeof(Elf64_Sym)) {
            Elf64_Sym sym {};
            maybe_read = process.read_memory(reinterpret_cast<void*>(cur_addr), &sym, sizeof(sym));
            if (!maybe_read.has_value()) {
                std::println(stderr,
                             "[inject] Failed to read symbol from target libc: {} ({})",
                             maybe_read.error().message(),
                             maybe_read.error().value());
                return std::nullopt;
            }

            if (sym.st_name == 0 || sym.st_value == 0)
                continue;

            std::array<char, sizeof(DLOPEN_SYMBOL_NAME)> name_buf {};
            maybe_read = process.read_memory(
                reinterpret_cast<void*>(str_tab_addr + sym.st_name), name_buf.data(), sizeof(name_buf));
            if (!maybe_read.has_value()) {
                std::println(stderr,
                             "[inject] Failed to read symbol name from target libc: {} ({})",
                             maybe_read.error().message(),
                             maybe_read.error().value());
                return std::nullopt;
            }

            if (std::strcmp(name_buf.data(), DLOPEN_SYMBOL_NAME) != 0)
                continue;

            ret = reinterpret_cast<void*>(libc_base_addr + sym.st_value);
            break;
        }

        if (ret != nullptr)
            break;
    }

    if (ret == nullptr)
        return std::nullopt;

    return ret;
}

bool inject_library(const std::filesystem::path& library_path, const process& process) {
    // Attach

    // Note to self:
    // ptrace goes: op, pid, addr, data
    // Meaning of addr and data changes depending on the ptrace request
    // See: man 2 ptrace

    const process::pid_t pid      = process.pid();
    const std::string    path_str = library_path.string();

    const auto attached = ptrace_cpp::attach_to_process(pid);
    if (!attached) {
        std::println(stderr,
                     "[ptrace] Failed to attach to remote process: {} ({})",
                     attached.error().message(),
                     attached.error().value());
        return false;
    }

    const auto first_wait = ptrace_cpp::wait_on_process(pid);
    if (std::get_if<ptrace_cpp::sig_stop_t>(&first_wait) == nullptr &&
        std::get_if<ptrace_cpp::syscall_info_t>(&first_wait) == nullptr) {
        std::println(stderr, "[inject] Remote process did not stop by signal or syscall");
        ptrace_cpp::debug::print_wait_status(first_wait);
        return false;
    }
    ptrace_cpp::debug::print_wait_status(first_wait);

    // Find a SYSCALL instruction (0x0f05) to jump from for use with mmap() & munmap()

    const auto libc_mem_regions = process.get_library_memory_regions(LIBC_SO_NAME);
    if (libc_mem_regions.empty()) {
        std::println(stderr, "[inject] Failed to get libc's memory map");
        return false;
    }

    const auto exec_region_it =
        std::find_if(libc_mem_regions.cbegin(), libc_mem_regions.cend(), [](const memory_region& r) {
            return r.execute;
        });

    const auto syscall_instn_locs =
        process.find_bytes_in_memory(reinterpret_cast<void*>(exec_region_it->start_addr),
                                     (exec_region_it->end_addr - exec_region_it->start_addr),
                                     SYSCALL_ENCODING);
    if (!syscall_instn_locs) {
        std::println(stderr,
                     "[inject] Failed to search for byte sequence in memory: {} ({})",
                     syscall_instn_locs.error().message(),
                     syscall_instn_locs.error().value());
        return false;
    }

    if (syscall_instn_locs.value().empty()) {
        std::println(stderr, "[inject] Did not find any SYSCALL instructions (0x0F05) sequences in memory");
        return false;
    }
    const auto& syscall_locs_vec = syscall_instn_locs.value();

    // Store signal & execution state

    const auto orig_regs = ptrace_cpp::get_regs(pid);
    if (!orig_regs) {
        std::println(stderr, "[inject] Failed to get remote process' register state");
        return false;
    }

    const auto set_opts = ptrace_cpp::set_options(pid, PTRACE_O_TRACESYSGOOD);
    if (!set_opts) {
        std::println(stderr,
                     "[ptrace] Failed to set ptrace options: {} ({})",
                     set_opts.error().message(),
                     set_opts.error().value());
        return false;
    }

    const auto target_loaded_libs = process.get_loaded_libraries();
    const auto target_libc_it = std::find_if(target_loaded_libs.cbegin(), target_loaded_libs.cend(), [](const auto& a) {
        return a.first.contains(LIBC_SO_NAME);
    });
    if (target_libc_it == target_loaded_libs.cend()) {
        std::println(stderr, "[inject] Failed to find libc in memory regions map");
        return false;
    }

    const auto dlopen = resolve_remote_dlopen(process, target_libc_it->second[0].start_addr);
    if (!dlopen.has_value()) {
        std::println(stderr, "[inject] Failed to resolve dlopen() in remote process' libc");
        return false;
    }

    std::println("[inject] Resolved dlopen() in remote process: {:#x}",
                 reinterpret_cast<std::uint64_t>(dlopen.value()));

    // Call mmap()

    const auto shcode_alloc_size   = std::bit_ceil(bin::dlopen_shellcode.size());
    const auto path_str_alloc_size = std::bit_ceil(path_str.size() + 1);
    const auto write_buf_size      = shcode_alloc_size + path_str_alloc_size;

    user_regs_struct mmap_regs = orig_regs.value();
    mmap_regs.rax              = syscalls::x64::mmap;                // mmap syscall number (x86_64)
    mmap_regs.rdi              = 0x0;                                // addr, NULL for any address
    mmap_regs.rsi              = write_buf_size;                     // length
    mmap_regs.rdx              = PROT_READ | PROT_WRITE | PROT_EXEC; // prot, all perms
    mmap_regs.r10              = MAP_PRIVATE | MAP_ANONYMOUS;        // flags
    mmap_regs.r8               = -1;                                 // fd, -1 seems to be "ignore" (?)
    mmap_regs.r9               = 0;                                  // offset
    mmap_regs.rip              = syscall_locs_vec[0];

    if (!ptrace_cpp::set_regs(pid, mmap_regs)) {
        std::println(stderr, "[ptrace] Failed to set register state for mmap() syscall");
        return false;
    }

    std::println("[inject] Calling mmap({:#x}, {}, {:#x}, {:#x}, {:#x}, {})",
                 mmap_regs.rdi,
                 mmap_regs.rsi,
                 mmap_regs.rdx,
                 mmap_regs.r10,
                 mmap_regs.r8,
                 mmap_regs.r9);

    bool           seen_mmap_entry   = false;
    bool           seen_mmap_exit    = false;
    std::uintptr_t remote_alloc_addr = 0;

    while (!(seen_mmap_entry && seen_mmap_exit)) {
        const auto cont = ptrace_cpp::continue_to_next_syscall(pid);
        if (!cont) {
            std::println(stderr,
                         "[ptrace] Failed to continue process execution: {} ({})",
                         cont.error().message(),
                         cont.error().value());
            return false;
        }

        const auto mmap_wait = ptrace_cpp::wait_on_process(pid);
        ptrace_cpp::debug::print_wait_status(mmap_wait);

        if (std::get_if<ptrace_cpp::syscall_stop_t>(&mmap_wait) == nullptr)
            continue;

        const auto& sys_stop = std::get<ptrace_cpp::syscall_stop_t>(mmap_wait);

        if (sys_stop.op == PTRACE_SYSCALL_INFO_ENTRY) {
            seen_mmap_entry = (sys_stop.entry.nr == syscalls::x64::mmap);
        } else if (sys_stop.op == PTRACE_SYSCALL_INFO_EXIT) {
            if (sys_stop.exit.is_error) {
                std::println(stderr, "[inject] mmap() syscall failed");
                return false;
            }

            remote_alloc_addr = sys_stop.exit.rval;
            seen_mmap_exit    = seen_mmap_entry;
        }
    }

    std::println("[inject] Allocated memory in remote process at {:#x}", remote_alloc_addr);

    std::vector<std::uint8_t> write_buf(write_buf_size);
    std::copy(bin::dlopen_shellcode.cbegin(), bin::dlopen_shellcode.cend(), write_buf.begin());
    const auto strcopy_end_it = std::copy(path_str.cbegin(), path_str.cend(), write_buf.begin() + shcode_alloc_size);
    *strcopy_end_it           = '\0'; // Null terminator

    const auto remote_lib_path_addr = remote_alloc_addr + shcode_alloc_size;
    std::println("[inject] Writing shellcode & library path to {:#x} and {:#x}, total {} bytes",
                 remote_alloc_addr,
                 remote_lib_path_addr,
                 write_buf.size());
    process.write_memory((void*) remote_alloc_addr, (void*) &write_buf[0], write_buf.size()).value();

    // Call the shellcode similarly to mmap

    user_regs_struct shellcode_regs = orig_regs.value();
    shellcode_regs.rip              = remote_alloc_addr;
    shellcode_regs.rdi              = reinterpret_cast<std::uintptr_t>(dlopen.value());
    shellcode_regs.rsi              = remote_lib_path_addr;

    if (!ptrace_cpp::set_regs(pid, shellcode_regs)) {
        std::println(stderr, "[ptrace] Failed to set register state for shellcode");
        return false;
    }
    std::println("[inject] Running shellcode ...");

    bool shellcode_success = false;

    while (!shellcode_success) {
        const auto cont = ptrace_cpp::continue_to_next_syscall(pid);
        if (!cont) {
            std::println(stderr,
                         "[ptrace] Failed to continue process execution: {} ({})",
                         cont.error().message(),
                         cont.error().value());
            return false;
        }

        const auto shellcode_wait = ptrace_cpp::wait_on_process(pid);
        ptrace_cpp::debug::print_wait_status(shellcode_wait);

        if (std::get_if<ptrace_cpp::syscall_stop_t>(&shellcode_wait)) {
            const auto sys_stop = std::get<ptrace_cpp::syscall_stop_t>(shellcode_wait);
            if (sys_stop.op == PTRACE_SYSCALL_INFO_ENTRY) {
                shellcode_success = (sys_stop.entry.nr == syscalls::x64::kill);
            }
        }
    }

    // Zero out the old memory

    std::fill(write_buf.begin(), write_buf.end(), '\0');
    process.write_memory((void*) remote_alloc_addr, &write_buf[0], write_buf_size).value();

    std::println("[inject] Zeroed memory in remote process");

    // Call munmap()
    // We end the shellcode on a syscall-enter-stop to kill(), swap orig_rax and wait for syscall-exit-stop

    user_regs_struct munmap_regs = orig_regs.value();
    munmap_regs.orig_rax         = syscalls::x64::munmap; // munmap syscall number (x86_64)
    munmap_regs.rdi              = remote_alloc_addr;     // addr
    munmap_regs.rsi              = write_buf_size;        // length

    std::println("[inject] Calling munmap({:#x}, {})", munmap_regs.rdi, munmap_regs.rsi);
    if (!ptrace_cpp::set_regs(pid, munmap_regs)) {
        std::println(stderr, "[ptrace] Failed to set register state for munmap() call");
        return false;
    }

    bool seen_munmap_exit = false;
    while (!seen_munmap_exit) {
        const auto cont = ptrace_cpp::continue_to_next_syscall(pid);
        if (!cont) {
            std::println(stderr,
                         "[ptrace] Failed to continue process execution: {} ({})",
                         cont.error().message(),
                         cont.error().value());
            return false;
        }

        const auto munmap_wait = ptrace_cpp::wait_on_process(pid);
        ptrace_cpp::debug::print_wait_status(munmap_wait);

        if (std::get_if<ptrace_cpp::syscall_stop_t>(&munmap_wait) == nullptr)
            continue;

        const auto sys_stop = std::get<ptrace_cpp::syscall_stop_t>(munmap_wait);

        if (sys_stop.op == PTRACE_SYSCALL_INFO_EXIT) {
            seen_munmap_exit = true;
            if (sys_stop.exit.is_error) {
                std::println(stderr, "[inject] WARNING: munmap() call failed");
            }
        }
    }

    std::println("[inject] Unmapped memory in remote process");

    // Restore regs and signal

    ptrace_cpp::set_regs(pid, orig_regs.value()).value();
    std::println("[inject] Restoring original register state");

    // Detach

    const auto detached = ptrace_cpp::detach_from_process(pid);
    if (!detached) {
        std::println(stderr,
                     "[ptrace] Remote process failed to detach: {} ({})",
                     detached.error().message(),
                     detached.error().value());
        return false;
    }

    std::println("[inject] Detached from remote process");

    return shellcode_success;
}
