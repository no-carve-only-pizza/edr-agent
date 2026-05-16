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
#
# 커널 버전 전용 bpftool을 우선 탐색한다.
# /usr/sbin/bpftool 은 linux-tools-common 패키지가 제공하는 shim 스크립트로,
# 실제 버전이 실행 중인 커널과 다를 수 있어 BPF ELF 릴로케이션 파싱 실패의
# 원인이 된다 ("Relocations in generic ELF (EM: 247)").
execute_process(COMMAND uname -r OUTPUT_VARIABLE KVER OUTPUT_STRIP_TRAILING_WHITESPACE)
find_program(BPFTOOL bpftool
    PATHS /usr/lib/linux-tools/${KVER}
    HINTS /usr/sbin /usr/local/sbin /usr/lib/linux-tools
    DOC "bpftool for BPF skeleton generation"
    REQUIRED)

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

# memory_monitor
set(MEM_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/memory_monitor.bpf.c)
set(MEM_BPF_OBJ  ${CMAKE_BINARY_DIR}/memory_monitor.bpf.o)
set(MEM_BPF_SKEL ${CMAKE_BINARY_DIR}/memory_monitor.skel.h)

# dns_monitor
set(DNS_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/dns_monitor.bpf.c)
set(DNS_BPF_OBJ  ${CMAKE_BINARY_DIR}/dns_monitor.bpf.o)
set(DNS_BPF_SKEL ${CMAKE_BINARY_DIR}/dns_monitor.skel.h)

# ns_monitor
set(NS_BPF_SRC  ${CMAKE_SOURCE_DIR}/bpf/ns_monitor.bpf.c)
set(NS_BPF_OBJ  ${CMAKE_BINARY_DIR}/ns_monitor.bpf.o)
set(NS_BPF_SKEL ${CMAKE_BINARY_DIR}/ns_monitor.skel.h)

# 공통 clang 플래그 (BPF 크로스 컴파일)
#
# -mcpu=v2: BPF ISA v2로 고정.
#   clang-14 + Ubuntu 22.04 환경에서 -mcpu 미지정 시 bpftool이 처리하지 못하는
#   릴로케이션 타입을 생성할 수 있다. v2는 커널 4.14+ 에서 지원하며
#   현재 지원 최소 커널(5.3)을 충족한다.
#   더 높은 커널/clang 버전에서는 -mcpu=v3 또는 -mcpu=probe 사용 가능.
set(BPF_CFLAGS
    -g -O2 -target bpf -mcpu=v2 -D__TARGET_ARCH_x86
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

# ── Step B-4: memory_monitor 컴파일 & 스켈레톤 생성 ─────────────────────
add_custom_command(
    OUTPUT  ${MEM_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${MEM_BPF_SRC} -o ${MEM_BPF_OBJ}
    DEPENDS ${MEM_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: memory_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${MEM_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${MEM_BPF_OBJ} > ${MEM_BPF_SKEL}
    DEPENDS ${MEM_BPF_OBJ}
    COMMENT "스켈레톤 생성: memory_monitor.skel.h"
    VERBATIM
)

# ── Step B-5: dns_monitor 컴파일 & 스켈레톤 생성 ─────────────────────────
add_custom_command(
    OUTPUT  ${DNS_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${DNS_BPF_SRC} -o ${DNS_BPF_OBJ}
    DEPENDS ${DNS_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: dns_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${DNS_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${DNS_BPF_OBJ} > ${DNS_BPF_SKEL}
    DEPENDS ${DNS_BPF_OBJ}
    COMMENT "스켈레톤 생성: dns_monitor.skel.h"
    VERBATIM
)

# ── Step B-6: ns_monitor 컴파일 & 스켈레톤 생성 ──────────────────────────
add_custom_command(
    OUTPUT  ${NS_BPF_OBJ}
    COMMAND ${CLANG} ${BPF_CFLAGS} -c ${NS_BPF_SRC} -o ${NS_BPF_OBJ}
    DEPENDS ${NS_BPF_SRC} ${VMLINUX_H}
    COMMENT "BPF 컴파일: ns_monitor.bpf.c"
    VERBATIM
)
add_custom_command(
    OUTPUT  ${NS_BPF_SKEL}
    COMMAND ${BPFTOOL} gen skeleton ${NS_BPF_OBJ} > ${NS_BPF_SKEL}
    DEPENDS ${NS_BPF_OBJ}
    COMMENT "스켈레톤 생성: ns_monitor.skel.h"
    VERBATIM
)

add_custom_target(bpf_build DEPENDS
    ${PROC_BPF_SKEL} ${FILE_BPF_SKEL} ${NET_BPF_SKEL}
    ${MEM_BPF_SKEL}  ${DNS_BPF_SKEL}  ${NS_BPF_SKEL}
)

# ── libcurl (마일스톤 5: HTTP 리포터) ────────────────────────────────────
find_package(CURL REQUIRED)

# ── 유저스페이스 실행 파일 ────────────────────────────────────────────────
add_executable(edr-agent
    src/main.cpp
    src/proc_tree.cpp
    src/rules/rule_engine.cpp
    src/rules/rule_config.cpp
    src/output/json_fmt.cpp
    src/output/http_reporter.cpp
    src/correlation/correlator.cpp
    src/threat_intel/feed_manager.cpp
    src/threat_intel/hash_checker.cpp
    src/anomaly/behavior_profiler.cpp
    src/action/action_server.cpp
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
    pthread
)

target_compile_options(edr-agent PRIVATE
    -Wall -Wextra -Wpedantic
)
