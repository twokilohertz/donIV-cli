#pragma once

#include <bitset>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <system_error>
#include <variant>

extern "C"
{
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/user.h>

#include <linux/ptrace.h> // Must be included after <sys/ptrace.h>
}

namespace ptrace_cpp
{
using void_expected_t         = std::expected<void, std::error_code>;
using int_expected_t          = std::expected<int, std::error_code>;
using syscall_info_t          = ptrace_syscall_info;
using syscall_info_expected_t = std::expected<syscall_info_t, std::error_code>;
using user_regs_t             = user_regs_struct;
using regs_expected_t         = std::expected<user_regs_t, std::error_code>;

struct sig_stop_t {
    int signal = 0;
};

struct exited_t {
    int exit_code = 0;
};

struct term_by_t {
    int term_sig = 0;
};

struct continued_t {};

using syscall_stop_t     = syscall_info_t; // ptrace_syscall_info
using wait_status_type_t = std::variant<sig_stop_t, syscall_stop_t, exited_t, term_by_t, continued_t, std::error_code>;

constexpr int TRACESYSGOOD_TRAP_MASK = (SIGTRAP | 0x80);

void_expected_t attach_to_process(std::uint32_t pid);
void_expected_t detach_from_process(std::uint32_t pid);
void_expected_t set_options(std::uint32_t pid, std::bitset<32> options);

regs_expected_t         get_regs(std::uint32_t pid);
syscall_info_expected_t get_syscall_info(std::uint32_t pid);
void_expected_t         set_regs(std::uint32_t pid, const user_regs_t& regs);

wait_status_type_t wait_on_process(std::uint32_t pid);
void_expected_t    continue_execution(std::uint32_t pid, int sig_num = 0);
void_expected_t    continue_to_next_syscall(std::uint32_t pid, int sig_num = 0);
void_expected_t    singlestep(std::uint32_t pid, int sig_num = 0);
} // namespace ptrace_cpp

namespace ptrace_cpp::status
{

inline int status_to_stop_sig(int status) noexcept {
    return WSTOPSIG(status);
}

inline bool is_stopped(int status) noexcept {
    return WIFSTOPPED(status);
}

inline bool is_exited(int status) noexcept {
    return WIFEXITED(status);
}

inline bool is_signalled(int status) noexcept {
    return WIFSIGNALED(status);
}

inline bool is_continued(int status) noexcept {
    return WIFCONTINUED(status);
}

} // namespace ptrace_cpp::status

namespace ptrace_cpp::signal
{

inline bool is_syscall(int sig_num) noexcept {
    return sig_num == TRACESYSGOOD_TRAP_MASK;
}

inline int unmask_sysgood(int sig_num) noexcept {
    return sig_num & 0x7F;
}

} // namespace ptrace_cpp::signal

namespace ptrace_cpp::debug
{

void print_user_regs(const user_regs_t& regs);
void print_wait_status(const wait_status_type_t& wait);

} // namespace ptrace_cpp::debug
