#pragma once

#include "process.hpp"

#include <filesystem>

bool inject_library(const std::filesystem::path& library_path, const process& process);
