cmake_minimum_required(VERSION 3.19)
project(redasm)

set(CMAKE_CXX_STANDARD 14)

include_directories(capstone)
include_directories(capstone/include)
include_directories(include)

add_executable(redasm
        capstone/include/arm.h
        capstone/include/arm64.h
        capstone/include/capstone.h
        capstone/include/mips.h
        capstone/include/platform.h
        capstone/include/ppc.h
        capstone/include/sparc.h
        capstone/include/systemz.h
        capstone/include/x86.h
        capstone/include/xcore.h
        include/baseblock.h
        include/pe.h
        include/redasm.h
        include/utility.h
        src/baseblock.cpp
        src/pe.cpp
        src/redasm.cpp
        src/utility.cpp
        test.cpp)
