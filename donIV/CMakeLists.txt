add_library(
    doniv
    STATIC
    src/process.cpp
    src/ptrace.cpp
    src/inject.cpp
)

target_compile_features(doniv PRIVATE cxx_std_23)
target_include_directories(doniv PUBLIC "include/")
add_subdirectory("shellcode/")
add_dependencies(doniv shellcode)

include(FetchContent)
target_link_libraries(doniv PRIVATE ctre)
target_include_directories(doniv PRIVATE ctre ${SHELLCODE_INCLUDE_DIR})

# Compile-Time Regular Expressions (CTRE)
FetchContent_Declare(
    ctre
    GIT_REPOSITORY https://github.com/hanickadot/compile-time-regular-expressions.git
    GIT_TAG v3.9.0
)
FetchContent_MakeAvailable(ctre)
