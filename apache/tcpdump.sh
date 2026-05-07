#!/usr/bin/env bash
# 컨테이너 내부 네트워크 인터페이스에서 패킷을 캡처하여 /pcap 볼륨에 시간 단위로 저장.
set -euo pipefail

PCAP_DIR="/pcap"
mkdir -p "$PCAP_DIR"

IFACE="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
IFACE="${IFACE:-eth0}"

echo "[tcpdump] capturing on interface: ${IFACE}"
echo "[tcpdump] writing rotated pcap files to ${PCAP_DIR}"

# -G 60 : 60초마다 새 파일로 회전
# -W 60 : 최대 60개 보관 (1시간 분량)
# -Z root : 권한 유지
exec tcpdump -i "${IFACE}" \
    -nn -s 0 \
    -G 60 -W 60 \
    -w "${PCAP_DIR}/capture-%Y%m%d-%H%M%S.pcap" \
    -Z root \
    'port 80'
