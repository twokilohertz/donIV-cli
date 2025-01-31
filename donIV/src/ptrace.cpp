#include "ptrace.hpp"

#include <asm/ptrace-abi.h>
#include <bitset>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <linux/ptrace.h>
#include <print>
#include <sys/ptrace.h>
#include <utility>

extern "C"
{
#include <sys/wait.h>
}

using pt_req = __ptrace_request;
using ptrace_cpp::int_expected_t;
using ptrace_cpp::regs_expected_t;
using ptrace_cpp::syscall_info_expected_t;
using ptrace_cpp::void_expected_t;
using ptrace_cpp::wait_status_type_t;

void_expected_t ptrace_cpp::attach_to_process(std::uint32_t pid) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_ATTACH), pid, nullptr, nullptr);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

void_expected_t ptrace_cpp::detach_from_process(std::uint32_t pid) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_DETACH), pid, nullptr, nullptr);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

void_expected_t ptrace_cpp::set_options(std::uint32_t pid, std::bitset<32> options) {
    const auto err = ::ptrace(static_cast<pt_req>(PT_SETOPTIONS), pid, nullptr, options.to_ulong());
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

regs_expected_t ptrace_cpp::get_regs(std::uint32_t pid) {
    user_regs_struct regs {};
    const auto       err = ::ptrace(static_cast<pt_req>(PTRACE_GETREGS), pid, nullptr, &regs);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return regs;
}

syscall_info_expected_t ptrace_cpp::get_syscall_info(std::uint32_t pid) {
    ptrace_syscall_info syscall_info {};
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_GET_SYSCALL_INFO), pid, sizeof(syscall_info), &syscall_info);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return syscall_info;
}

void_expected_t ptrace_cpp::set_regs(std::uint32_t pid, const user_regs_t& regs) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_SETREGS), pid, nullptr, &regs);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

wait_status_type_t ptrace_cpp::wait_on_process(std::uint32_t pid) {
    int        status = 0;
    const auto err    = ::waitpid(pid, &status, 0);
    if (err < 0) {
        return std::make_error_code(static_cast<std::errc>(errno));
    }

    if (WIFSTOPPED(status)) {
        const int signal = ptrace_cpp::status::status_to_stop_sig(status);
        if (ptrace_cpp::signal::is_syscall(signal)) {
            auto syscall_info = ptrace_cpp::get_syscall_info(pid);
            if (!syscall_info)
                return std::make_error_code(static_cast<std::errc>(errno));

            return ptrace_cpp::syscall_stop_t(syscall_info.value());
        } else {
            return ptrace_cpp::sig_stop_t(signal);
        }
    } else if (WIFEXITED(status)) {
        return ptrace_cpp::exited_t(WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        return ptrace_cpp::term_by_t(WTERMSIG(status));
    } else if (WIFCONTINUED(status)) {
        return ptrace_cpp::continued_t();
    } else {
        return ptrace_cpp::continued_t();
    }

    return ptrace_cpp::continued_t();
}

void_expected_t ptrace_cpp::continue_execution(std::uint32_t pid, int sig_num) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_CONT), pid, nullptr, sig_num);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

void_expected_t ptrace_cpp::continue_to_next_syscall(std::uint32_t pid, int sig_num) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_SYSCALL), pid, nullptr, sig_num);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

void_expected_t ptrace_cpp::singlestep(std::uint32_t pid, int sig_num) {
    const auto err = ::ptrace(static_cast<pt_req>(PTRACE_SINGLESTEP), pid, nullptr, sig_num);
    if (err < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

void ptrace_cpp::debug::print_user_regs(const user_regs_t& regs) {
    std::println("[ptrace] -- RIP: {:#018x}", regs.rip);
    std::println("[ptrace] -- RAX: {:#018x} (Original)", regs.orig_rax);
    std::println("[ptrace] -- RAX: {:#018x}", regs.rax);
    std::println("[ptrace] -- RBX: {:#018x}", regs.rbx);
    std::println("[ptrace] -- RCX: {:#018x}", regs.rcx);
    std::println("[ptrace] -- RDX: {:#018x}", regs.rdx);
    std::println("[ptrace] -- RDI: {:#018x}", regs.rdi);
    std::println("[ptrace] -- RSI: {:#018x}", regs.rsi);
    return;
}

void ptrace_cpp::debug::print_wait_status(const wait_status_type_t& wait) {
    std::visit(
        [&wait](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, ptrace_cpp::sig_stop_t>) {
                const auto sig_stop = std::get<ptrace_cpp::sig_stop_t>(wait);
                std::println("[ptrace] -- Signal stop: {} ({})", strsignal(sig_stop.signal), sig_stop.signal);
            } else if constexpr (std::is_same_v<T, ptrace_cpp::syscall_stop_t>) {
                const auto sys_stop = std::get<ptrace_cpp::syscall_stop_t>(wait);
                if (sys_stop.op == PTRACE_SYSCALL_INFO_ENTRY) {
                    std::println("[ptrace] -- Syscall entry: {}", sys_stop.entry.nr);
                } else if (sys_stop.op == PTRACE_SYSCALL_INFO_EXIT) {
                    std::println("[ptrace] -- Syscall exit: {}, {}",
                                 sys_stop.exit.is_error ? "error" : "success",
                                 sys_stop.exit.rval);
                }
            } else if constexpr (std::is_same_v<T, ptrace_cpp::exited_t>)
                std::println("[ptrace] -- Process exited: {}", std::get<ptrace_cpp::exited_t>(wait).exit_code);
            else if constexpr (std::is_same_v<T, ptrace_cpp::term_by_t>)
                std::println("[ptrace] -- Process terminated by signal: {}",
                             std::get<ptrace_cpp::term_by_t>(wait).term_sig);
            else if constexpr (std::is_same_v<T, ptrace_cpp::continued_t>)
                std::println("[ptrace] -- Continued ...");
            else if constexpr (std::is_same_v<T, std::error_code>) {
                const std::error_code& err = std::get<std::error_code>(wait);
                std::println("[ptrace] -- Error: {} ({})", err.message(), err.value());
            } else
                static_assert(false, "non-exhaustive visitor!");
        },
        wait);
    return;
}
