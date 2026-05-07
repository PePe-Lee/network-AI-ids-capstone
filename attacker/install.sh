#!/bin/bash
set -e

# 기존 미러 전부 제거하고 공식 미러만 등록
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
    > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*

# APT SSL 검증 비활성화
echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99no-ssl-verify
echo 'Acquire::https::Verify-Host "false";' >> /etc/apt/apt.conf.d/99no-ssl-verify

apt-get clean
apt-get update
apt-get install -y \
    hping3 \
    nmap \
    curl \
    hydra \
    sqlmap \
    python3 \
    python3-scapy \
    iproute2 \
    iputils-ping \
    net-tools

tail -f /dev/null
