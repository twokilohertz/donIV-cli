set(
    SHELLCODE_INCLUDE_DIR
    ${CMAKE_CURRENT_BINARY_DIR}
    PARENT_SCOPE
)

set(
    SHELLCODE_OUT_DIR
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_command(
    OUTPUT ${SHELLCODE_OUT_DIR}/dlopen_shellcode.o
    COMMAND as --64 -o ${SHELLCODE_OUT_DIR}/dlopen_shellcode.o ./dlopen_shellcode.s
    DEPENDS ./dlopen_shellcode.s
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Assemble dlopen() shellcode (x86_64)"
)

add_custom_command(
    OUTPUT ${SHELLCODE_OUT_DIR}/dlopen_shellcode.bin
    COMMAND objcopy -j .text -O binary ${SHELLCODE_OUT_DIR}/dlopen_shellcode.o ${SHELLCODE_OUT_DIR}/dlopen_shellcode.bin
    DEPENDS ${SHELLCODE_OUT_DIR}/dlopen_shellcode.o
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Copy dlopen() shellcode to binary file (x86_64)"
)

add_custom_command(
    OUTPUT ${SHELLCODE_OUT_DIR}/dlopen_shellcode.hpp
    COMMAND python bin2cppheader.py ${SHELLCODE_OUT_DIR}/dlopen_shellcode.bin
    DEPENDS ${SHELLCODE_OUT_DIR}/dlopen_shellcode.bin
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Convert dlopen() shellcode binary to C++ header (x86_64)"
)

add_custom_target(
    shellcode
    DEPENDS ${SHELLCODE_OUT_DIR}/dlopen_shellcode.hpp
)
