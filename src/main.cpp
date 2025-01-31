#include "cli.hpp"
#include "inject.hpp"
#include "process.hpp"

#include <cstdlib>
#include <print>

int main(int argc, char* argv[]) {
    const auto maybe_cli_args = cli::try_construct(argc, argv);

    if (!maybe_cli_args.has_value()) {
        const auto err = maybe_cli_args.error();
        std::println(stderr, "{}", cli::cli_parse_err_str(err));
        cli::print_usage();
        return EXIT_FAILURE;
    }

    const auto& cli_args = maybe_cli_args.value();

    process proc(cli_args.process_id);
    std::println("[doniv-cli] Process ID: {}", proc.pid());
    std::println("[doniv-cli] Binary path: {}", proc.get_exe_path()->c_str());

    if (!inject_library(cli_args.library_path, proc)) {
        std::println("[inject] Failed to inject");
        return EXIT_FAILURE;
    }

    std::println("[inject] Successfully injected");
    return EXIT_SUCCESS;
}
