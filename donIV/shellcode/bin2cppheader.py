# bin2cppheader.py
# Convert a binary file to its static std::array representation as an
# includable header file in your C++ project.
# Author:   Adam Macdonald [https://github.com/twokilohertz]
# License:  MIT License

usage = "Usage: python bin2cppheader.py in_file [out_file]"

import sys
import mmap
from pathlib import Path

# Helper function for printing to stderr
def eprint(*args, **kwargs):
    return print(*args, file=sys.stderr, **kwargs)

def read_bin(bin_path):
    ret_buf = []

    with open(bin_path, "rb") as f:
        with mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ) as mm:
            ret_buf = mm.read()
            return ret_buf
    
    return ret_buf

def bin_to_header(data, symbol_name, namespace = "bin"):
    ret_str = "#pragma once\n#include <array>\n#include <cstdint>\nnamespace " + namespace + " { constexpr const std::array<std::uint8_t, "+ str(len(data)) + "> " + symbol_name + " {"

    for b in data:
        ret_str += "{:#04x}".format(b) + ", "

    ret_str = ret_str[:-2]
    ret_str += "};}"

    return ret_str

if __name__ == "__main__":
    if len(sys.argv) < 2:
        eprint(usage)
        exit(1)
    
    # Some validation on the input path
    in_path = Path(sys.argv[1])
    if not in_path.exists():
        eprint("input path does not exist")
        exit(1)
    if not in_path.is_file():
        eprint("input path is not a file")
        exit(1)

    # Read data & convert to a string of valid C++
    data = read_bin(in_path)
    header_str = bin_to_header(data, in_path.stem)

    out_path = Path()

    if len(sys.argv) == 3:
        out_path = Path(sys.argv[2])
        if not out_path.exists():
            eprint("output path does not exist")
            exit(1)
        if not out_path.is_dir():
            eprint("output path is not a directory")
            exit(1)
    else:
        out_path = in_path.parents[0] / f"{in_path.stem}.hpp"
    
    with open(out_path, "w") as f:
        f.write(header_str)
    
    exit(0)
