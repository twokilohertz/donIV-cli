#include "process.hpp"

#include <ctre.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <print>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

extern "C"
{
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
}

std::expected<std::size_t, std::error_code> process::read_memory(void*       target_addr,
                                                                 void*       local_addr,
                                                                 std::size_t len) const noexcept {
    const iovec local {.iov_base = local_addr, .iov_len = len};
    const iovec remote {.iov_base = target_addr, .iov_len = len};

    const auto n_bytes_read = process_vm_readv(m_process_id, &local, 1, &remote, 1, 0);
    if (n_bytes_read <= 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return n_bytes_read;
}

std::expected<std::size_t, std::error_code> process::write_memory(void*       target_addr,
                                                                  void*       local_addr,
                                                                  std::size_t len) const noexcept {
    const iovec local {.iov_base = local_addr, .iov_len = len};
    const iovec remote {.iov_base = target_addr, .iov_len = len};

    const auto n_bytes_written = process_vm_writev(m_process_id, &local, 1, &remote, 1, 0);
    if (n_bytes_written <= 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return n_bytes_written;
}

std::expected<std::vector<std::uintptr_t>, std::error_code> process::find_bytes_in_memory(
    void* start_addr, std::size_t len, std::span<const std::uint8_t> bytes) const noexcept {
    static constexpr const std::size_t max_fetch_size = 0x1000;
    const std::size_t                  fetch_size     = (len < max_fetch_size) ? len : max_fetch_size;
    std::vector<std::uintptr_t>        ret_vec;

    std::vector<std::uint8_t> buf(fetch_size);

    for (std::size_t offset = 0; offset < len; offset += fetch_size) {
        const auto read_addr  = reinterpret_cast<std::uintptr_t>(start_addr) + offset;
        const auto bytes_read = read_memory(reinterpret_cast<void*>(read_addr), &buf[0], fetch_size);
        if (!bytes_read) {
            return std::unexpected(bytes_read.error());
        }

        auto it = buf.cbegin();
        while (it != buf.cend()) {
            it = std::search(it, buf.cend(), bytes.cbegin(), bytes.cend());
            if (it == buf.cend())
                continue;

            ret_vec.push_back(read_addr + std::distance(buf.cbegin(), it));
            std::advance(it, bytes.size());
        }
    }

    return ret_vec;
}

std::expected<void, std::error_code> process::send_signal(int signum) const noexcept {
    if (kill(m_process_id, signum) < 0) {
        return std::unexpected(std::make_error_code(static_cast<std::errc>(errno)));
    }

    return {};
}

std::optional<std::filesystem::path> process::get_exe_path() const {
    std::filesystem::path proc_exe_path(std::format("/proc/{}/exe", m_process_id));

    try {
        const auto exists     = std::filesystem::exists(proc_exe_path);
        const auto is_symlink = std::filesystem::is_symlink(proc_exe_path);

        if (exists && is_symlink) {
            return std::filesystem::read_symlink(proc_exe_path);
        } else {
            return std::nullopt;
        }
    } catch (const std::filesystem::filesystem_error& ex) {
        return std::nullopt;
    }
};

std::vector<memory_region> process::get_memory_regions() const {
    std::vector<memory_region> ret_vec;

    const std::filesystem::path proc_maps_path(std::format("/proc/{}/maps", m_process_id));
    std::ifstream               stream(proc_maps_path, std::ios::in);

    static constexpr auto regex_string = ctll::fixed_string {
        R"(^([0-9a-fA-F]+)\-([0-9a-fA-F]+)\s([r|w|x|s|p|\-]{4})\s([0-9a-fA-F]+)\s([0-9a-fA-F]{2}):(["
        "0-9a-fA-F]{2})\s(\d+)\s+(.*)$)"};

    std::string curr_line;
    while (!stream.eof() && !stream.bad()) {
        std::getline(stream, curr_line);
        if (curr_line.empty())
            continue;

        const auto match = ctre::match<regex_string>(curr_line);

        const auto         start_addr  = std::stoull(match.get<1>().str(), 0, 16);
        const auto         end_addr    = std::stoull(match.get<2>().str(), 0, 16);
        const auto&        permissions = match.get<3>().str();
        const auto         offset      = std::stoull(match.get<4>().str(), 0, 16);
        const std::uint8_t dev_major   = stoul(match.get<5>().str(), 0, 16);
        const std::uint8_t dev_minor   = stoul(match.get<6>().str(), 0, 16);
        const auto         inode       = stoull(match.get<7>().str(), 0, 10);
        const auto         path_name   = match.get<8>().str();

        ret_vec.emplace_back(start_addr,
                             end_addr,
                             offset,
                             path_name,
                             dev_major,
                             dev_minor,
                             inode,
                             permissions[0] == 'r',
                             permissions[1] == 'w',
                             permissions[2] == 'x',
                             permissions[3] == 'p',
                             permissions[3] == 's');
    }

    return ret_vec;
}

std::vector<memory_region> process::get_library_memory_regions(std::string_view lib_name) const {
    const auto memory_regions = get_memory_regions();

    std::vector<memory_region> lib_mem_regions;
    std::copy_if(memory_regions.cbegin(),
                 memory_regions.cend(),
                 std::back_inserter(lib_mem_regions),
                 [&lib_name](const auto& x) {
                     return x.path_name.contains(lib_name);
                 });
    return lib_mem_regions;
}

process::lib_map_t process::get_loaded_libraries() const {
    process::lib_map_t ret_map {};
    const auto         memory_regions = get_memory_regions();
    ret_map.reserve(memory_regions.size());

    for (const auto& region : memory_regions) {
        if (region.path_name.empty())
            continue;

        if (ret_map.contains(region.path_name)) {
            auto& it = ret_map.at(region.path_name);
            it.push_back(region);
        } else {
            std::vector<memory_region> new_v {};
            auto                       inserted = ret_map.insert({region.path_name, std::move(new_v)});
            if (inserted.second)
                inserted.first->second.push_back(region);
        }
    }

    return ret_map;
}
