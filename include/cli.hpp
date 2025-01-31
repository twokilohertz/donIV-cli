#pragma once

#include "process.hpp"

#include <cstdint>
#include <expected>
#include <string_view>

enum class cli_parse_err : std::uint8_t {
    missing_target_process,
    missing_library_path,
    invalid_argument,
    not_enough_args,
};

using std::operator""sv;

class cli {
  public:
    static std::expected<cli, cli_parse_err> try_construct(int argc, char** argv);

    static void             print_usage();
    static std::string_view cli_parse_err_str(cli_parse_err err);

  public:
    process::pid_t        process_id = process::INVALID_PID;
    std::filesystem::path library_path;
};
