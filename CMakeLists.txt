cmake_minimum_required(VERSION 3.20)

project(
    doniv-cli
    VERSION 0.1
    DESCRIPTION "donIV injector"
    LANGUAGES CXX
)

# Depends on donIV library
add_subdirectory("donIV/")

add_executable(
    doniv-cli
    src/main.cpp
    src/cli.cpp
)
target_compile_features(doniv-cli PRIVATE cxx_std_23)
target_link_libraries(doniv-cli doniv ctre)
target_include_directories(doniv-cli PRIVATE "include/" ctre)

# Compile-Time Regular Expressions (CTRE)
FetchContent_Declare(
    ctre
    GIT_REPOSITORY https://github.com/hanickadot/compile-time-regular-expressions.git
    GIT_TAG v3.9.0
)
FetchContent_MakeAvailable(ctre)
