cmake_minimum_required(VERSION 3.16)
project(edr-agent VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD            11)
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Cursor / clangd LSP 지원용 compile_commands.json 생성
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── 의존성 탐색 ───────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

# libbpf: BPF 시스템 콜 래퍼 라이브러리
# Ubuntu: sudo apt install libbpf-dev
pkg_check_modules(LIBBPF REQUIRED libbpf)

# clang: BPF 프로그램을 BPF ISA로 크로스 컴파일
find_program(CLANG clang REQUIRED
    HINTS /usr/bin /usr/local/bin
    DOC "Clang compiler for BPF programs")

# bpftool: vmlinux.h 생성 + 스켈레톤 헤더 생성
# Ubuntu: sudo apt install linux-tools-$(uname -r) linux-tools-common
find_program(BPFTOOL bpftool
    HINTS /usr/sbin /usr/lib/linux-tools
          # uname -r 기반 경로를 fallback으로 탐색
    DOC "bpftool for BPF skeleton generation")
if(NOT BPFTOOL)
    # linux-tools-$(uname -r) 경로 직접 탐색
    execute_process(COMMAND uname -r OUTPUT_VARIABLE KVER OUTPUT_STRIP_TRAILING_WHITESPACE)
    find_program(BPFTOOL bpftool
        PATHS /usr/lib/linux-tools/${KVER}
        REQUIRED)
endif()

message(STATUS "clang:   ${CLANG}")
message(STATUS "bpftool: ${BPFTOOL}")

# ── 경로 정의 ─────────────────────────────────────────────────────────────
set(VMLINUX_H ${CMAKE_BINARY_DIR}/vmlinux.h)

# process_monitor
set(PROC_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/process_monitor.bpf.c)
set(PROC_BPF_OBJ  ${CMAKE_BINARY_DIR}/process_monitor.bpf.o)
set(PROC_BPF_SKEL ${CMAKE_BINARY_DIR}/process_monitor.skel.h)

# file_monitor
set(FILE_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/file_monitor.bpf.c)
set(FILE_BPF_OBJ  ${CMAKE_BINARY_DIR}/file_monitor.bpf.o)
set(FILE_BPF_SKEL ${CMAKE_BINARY_DIR}/file_monitor.skel.h)

# network_monitor
set(NET_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/network_monitor.bpf.c)
set(NET_BPF_OBJ  ${CMAKE_BINARY_DIR}/network_monitor.bpf.o)
set(NET_BPF_SKEL ${CMAKE_BINARY_DIR}/network_monitor.skel.h)

# 공통 clang 플래그 (BPF 크로스 컴파일)
set(BPF_CFLAGS
    -g -O2 -target bpf -D__TARGET_ARCH_x86
    -I${CMAKE_BINARY_DIR}
    -I${CMAKE_SOURCE_DIR}/include
    -I${LIBBPF_INCLUDE_DIRS}
)

# ── Step A: vmlinux.h 생성 ────────────────────────────────────────────────
add_custom_command(
    OUTPUT  ${VMLINUX_H}
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c
            > ${VMLINUX_H}
    COMMENT "vmlinux.h 생성: BTF → C 타입 덤프"
    VERBATIM
)

# ── Step B-1: process_monitor 컴파일 & 스켈레톤 생성 ─────────────────────
add_custom_command(
    OUTPUT  ${PROC_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${PROC_BPF_SRC} -o ${PROC_BPF_OBJ}
    DEPENDS ${PROC_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: process_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${PROC_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${PROC_BPF_OBJ} > ${PROC_BPF_SKEL}
    DEPENDS ${PROC_BPF_OBJ}
    COMMENT "스켈레톤 생성: process_monitor.skel.h"
    VERBATIM
)

# ── Step B-2: file_monitor 컴파일 & 스켈레톤 생성 ────────────────────────
add_custom_command(
    OUTPUT  ${FILE_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${FILE_BPF_SRC} -o ${FILE_BPF_OBJ}
    DEPENDS ${FILE_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: file_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${FILE_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${FILE_BPF_OBJ} > ${FILE_BPF_SKEL}
    DEPENDS ${FILE_BPF_OBJ}
    COMMENT "스켈레톤 생성: file_monitor.skel.h"
    VERBATIM
)

# ── Step B-3: network_monitor 컴파일 & 스켈레톤 생성 ─────────────────────
add_custom_command(
    OUTPUT  ${NET_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${NET_BPF_SRC} -o ${NET_BPF_OBJ}
    DEPENDS ${NET_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: network_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${NET_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${NET_BPF_OBJ} > ${NET_BPF_SKEL}
    DEPENDS ${NET_BPF_OBJ}
    COMMENT "스켈레톤 생성: network_monitor.skel.h"
    VERBATIM
)

add_custom_target(bpf_build DEPENDS ${PROC_BPF_SKEL} ${FILE_BPF_SKEL} ${NET_BPF_SKEL})

# ── libcurl (마일스톤 5: HTTP 리포터) ────────────────────────────────────
find_package(CURL REQUIRED)

# ── 유저스페이스 실행 파일 ────────────────────────────────────────────────
add_executable(edr-agent
    src/main.cpp
    src/rules/rule_engine.cpp
    src/output/json_fmt.cpp
    src/output/http_reporter.cpp
)

add_dependencies(edr-agent bpf_build)

target_include_directories(edr-agent PRIVATE
    ${CMAKE_BINARY_DIR}            # *.skel.h, vmlinux.h
    ${CMAKE_SOURCE_DIR}/include    # common.h
    ${CMAKE_SOURCE_DIR}/src        # rules/, output/ 헤더
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(edr-agent PRIVATE
    ${LIBBPF_LIBRARIES}
    CURL::libcurl
    elf
    z
)

target_compile_options(edr-agent PRIVATE
    -Wall -Wextra -Wpedantic
)
