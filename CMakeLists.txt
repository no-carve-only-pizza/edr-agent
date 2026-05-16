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
# cmake find_program 탐색 순서: HINTS → 시스템 경로 → PATHS
# 커널 버전 전용 경로를 HINTS에 넣어야 /usr/sbin/bpftool(shim)보다 먼저 선택된다.
execute_process(COMMAND uname -r OUTPUT_VARIABLE KVER OUTPUT_STRIP_TRAILING_WHITESPACE)
find_program(BPFTOOL bpftool
    HINTS /usr/lib/linux-tools/${KVER}
    PATHS /usr/sbin /usr/local/sbin /usr/lib/linux-tools
    DOC "bpftool for BPF skeleton generation"
    REQUIRED)

# llvm-strip: BPF 오브젝트에서 DWARF 섹션 제거용
# clang -g 는 BTF(.BTF/.BTF.ext)와 DWARF(.debug_*) 를 모두 생성한다.
# bpftool(libbpf v1.4 이하)은 .debug_* 릴로케이션을 처리하지 못해
# "Relocations in generic ELF (EM: 247)" 에러를 낸다.
# llvm-strip --strip-debug 로 DWARF만 제거하면 BTF는 그대로 유지된다.
find_program(LLVM_STRIP
    NAMES llvm-strip llvm-strip-18 llvm-strip-17 llvm-strip-16
          llvm-strip-15 llvm-strip-14 llvm-strip-13
    HINTS /usr/bin /usr/local/bin
    DOC "llvm-strip for stripping DWARF from BPF objects")
if(NOT LLVM_STRIP)
    message(WARNING "llvm-strip 을 찾지 못했습니다. BPF DWARF 제거 단계를 건너뜁니다.\n"
                    "  Ubuntu: sudo apt install llvm")
endif()
message(STATUS "llvm-strip: ${LLVM_STRIP}")

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

# BPF 컴파일 + DWARF 제거 + 스켈레톤 생성 매크로
# clang -g 로 컴파일 후 llvm-strip --strip-debug 로 .debug_* 섹션만 제거.
# .BTF / .BTF.ext 는 SHT_PROGBITS 이름 기반이라 --strip-debug 영향 없음.
macro(bpf_target NAME SRC OBJ SKEL)
    add_custom_command(
        OUTPUT  ${OBJ}
        COMMAND ${CLANG} ${BPF_CFLAGS} -c ${SRC} -o ${OBJ}
        COMMAND $<IF:$<BOOL:${LLVM_STRIP}>,${LLVM_STRIP},true>
                --strip-debug ${OBJ}
        DEPENDS ${SRC} ${VMLINUX_H}
        COMMENT "BPF 컴파일 + DWARF 제거: ${NAME}"
        VERBATIM
    )
    add_custom_command(
        OUTPUT  ${SKEL}
        COMMAND ${BPFTOOL} gen skeleton ${OBJ} > ${SKEL}
        DEPENDS ${OBJ}
        COMMENT "스켈레톤 생성: ${NAME}.skel.h"
        VERBATIM
    )
endmacro()

# ── Step B-1 ~ B-6: 각 BPF 프로그램 빌드 ────────────────────────────────
bpf_target(process_monitor ${PROC_BPF_SRC} ${PROC_BPF_OBJ} ${PROC_BPF_SKEL})
bpf_target(file_monitor    ${FILE_BPF_SRC} ${FILE_BPF_OBJ} ${FILE_BPF_SKEL})
bpf_target(network_monitor ${NET_BPF_SRC}  ${NET_BPF_OBJ}  ${NET_BPF_SKEL})
bpf_target(memory_monitor  ${MEM_BPF_SRC}  ${MEM_BPF_OBJ}  ${MEM_BPF_SKEL})
bpf_target(dns_monitor     ${DNS_BPF_SRC}  ${DNS_BPF_OBJ}  ${DNS_BPF_SKEL})
bpf_target(ns_monitor      ${NS_BPF_SRC}   ${NS_BPF_OBJ}   ${NS_BPF_SKEL})

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
