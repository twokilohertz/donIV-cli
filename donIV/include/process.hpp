#pragma once

#include <cassert>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class memory_region {
  public:
    std::uintptr_t start_addr = 0x0;
    std::uintptr_t end_addr   = 0x0;
    std::uintptr_t offset     = 0x0;
    std::string    path_name;
    std::uint8_t   dev_major = 0;
    std::uint8_t   dev_minor = 0;
    std::uint64_t  inode     = 0;
    bool           read      = false;
    bool           write     = false;
    bool           execute   = false;
    bool           priv      = false;
    bool           shared    = false;
};

class process {
  public:
    using pid_t                        = std::uint32_t;
    using lib_map_t                    = std::unordered_map<std::string, std::vector<memory_region>>;
    static constexpr pid_t INVALID_PID = 0;

    process(pid_t pid)
        : m_process_id(pid) {};

  public:
    inline pid_t pid() const noexcept {
        return m_process_id;
    }

    std::expected<std::size_t, std::error_code>                 read_memory(void*       target_addr,
                                                                            void*       local_addr,
                                                                            std::size_t len) const noexcept;
    std::expected<std::size_t, std::error_code>                 write_memory(void*       target_addr,
                                                                             void*       local_addr,
                                                                             std::size_t len) const noexcept;
    std::expected<std::vector<std::uintptr_t>, std::error_code> find_bytes_in_memory(
        void* start_addr, std::size_t len, std::span<const std::uint8_t> bytes) const noexcept;
    std::expected<void, std::error_code> send_signal(int signum) const noexcept;

    std::optional<std::filesystem::path> get_exe_path() const;
    std::vector<memory_region>           get_memory_regions() const;
    std::vector<memory_region>           get_library_memory_regions(std::string_view lib_name) const;
    lib_map_t                            get_loaded_libraries() const;

  private:
    pid_t m_process_id = INVALID_PID;
};
