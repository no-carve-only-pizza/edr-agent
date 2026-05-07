#!/bin/bash
# setup.sh - 의존성 설치 + 빌드 + 실행 원스톱 스크립트
set -e

KVER=$(uname -r)

echo "[1/3] 의존성 설치..."
sudo apt-get install -y \
    clang llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    linux-tools-common \
    linux-tools-"${KVER}" \
    cmake pkg-config

echo "[2/3] 빌드..."
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j"$(nproc)"
cd ..

echo "[3/3] 실행 (root 필요)..."
sudo ./build/edr-agent
