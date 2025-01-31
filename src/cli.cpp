#include "cli.hpp"
#include "process.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <limits>
#include <print>
#include <span>
#include <string_view>

using std::operator""sv;

void cli::print_usage() {
    std::println("Usage: doniv-cli [-P process_name | -p process_id] -L library_path");
    return;
}
std::string_view cli::cli_parse_err_str(cli_parse_err err) {
    switch (err) {
    case cli_parse_err::missing_target_process:
        return "Missing target process identifier (process name/PID)"sv;
    case cli_parse_err::missing_library_path:
        return "Missing path to library to inject"sv;
    case cli_parse_err::invalid_argument:
        return "Invalid command line arguments"sv;
    case cli_parse_err::not_enough_args:
        return "Not enough command line parameters"sv;
    default:
        return ""sv;
    }
}

std::expected<cli, cli_parse_err> cli::try_construct(int argc, char** argv) {
    if (argc < 5) {
        return std::unexpected(cli_parse_err::not_enough_args);
    }

    const std::span<char*> cli_args(argv, argc);
    int                    proc_name_arg_idx = 0;
    int                    proc_pid_arg_idx  = 0;
    int                    lib_path_arg_idx  = 0;

    for (int i = 0; i < cli_args.size(); ++i) {
        const auto& arg      = cli_args[i];
        const int   next_idx = (i + 1);

        if (std::strcmp(arg, "-P") == 0) {
            if (next_idx < cli_args.size()) {
                proc_name_arg_idx = next_idx;
            }
        } else if (std::strcmp(arg, "-p") == 0) {
            if (next_idx < cli_args.size()) {
                proc_pid_arg_idx = next_idx;
            }
        } else if (std::strcmp(arg, "-L") == 0) {
            if (next_idx < cli_args.size()) {
                lib_path_arg_idx = next_idx;
            }
        }
    }

    if (!proc_name_arg_idx && !proc_pid_arg_idx) {
        return std::unexpected(cli_parse_err::missing_target_process);
    }

    if (!lib_path_arg_idx) {
        return std::unexpected(cli_parse_err::missing_library_path);
    }

    if (proc_pid_arg_idx) {
        // Specify process by PID (takes priority over process name)
        const auto& pid_str    = cli_args[proc_pid_arg_idx];
        const auto  parsed_pid = std::strtoul(pid_str, nullptr, 0);
        return cli {static_cast<process::pid_t>(parsed_pid), std::filesystem::path(cli_args[lib_path_arg_idx])};
    } else {
        // Specify process by process name
        for (const auto& procfs_entry : std::filesystem::directory_iterator("/proc/")) {
            // Not a directory
            if (!procfs_entry.is_directory())
                continue;

            std::string_view dir_name(procfs_entry.path().filename().c_str());
            const bool       is_dir_name_numeric = std::all_of(dir_name.cbegin(), dir_name.cend(), [](const char c) {
                return std::isdigit(c);
            });

            // Ensure this is a PID directory
            if (!is_dir_name_numeric)
                continue;

            // Ensure "exe" file node exists
            const auto proc_exe_path = procfs_entry.path() / "exe";

            try {
                const auto exists     = std::filesystem::exists(proc_exe_path);
                const auto is_symlink = std::filesystem::is_symlink(proc_exe_path);

                if (!exists || !is_symlink) {
                    continue;
                }

                const auto bin_path = std::filesystem::read_symlink(proc_exe_path);
                if (bin_path.filename().string().compare(cli_args[proc_name_arg_idx]) == 0) {
                    const auto pid = std::strtoul(procfs_entry.path().filename().c_str(), nullptr, 0);

                    if (pid == 0) {
                        return std::unexpected(cli_parse_err::invalid_argument);
                    }

                    if (pid > std::numeric_limits<process::pid_t>::max() || errno == ERANGE) {
                        return std::unexpected(cli_parse_err::invalid_argument);
                    }

                    return cli {static_cast<process::pid_t>(pid), std::filesystem::path(cli_args[lib_path_arg_idx])};
                } else {
                    continue;
                }
            } catch (const std::filesystem::filesystem_error& ex) {
                // Missing permissions (?)
                continue;
            }
        }
    }

    return std::unexpected(cli_parse_err::missing_target_process);
}
