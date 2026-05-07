#!/bin/bash
# 30개 위조 IP DDoS 시뮬레이션 실행 스크립트
# scapy SYN 스푸핑으로 다수 공격자를 흉내냄

TARGET=${1:-apache_server}
PORT=${2:-80}
ATTACKERS=${3:-30}
DURATION=${4:-30}

echo "[ddos_attack.sh] 대상       : ${TARGET}:${PORT}"
echo "[ddos_attack.sh] 위조 공격자: ${ATTACKERS}명"
echo "[ddos_attack.sh] 지속 시간  : ${DURATION}초"
echo ""

# scapy 설치 확인
if ! python3 -c "from scapy.all import IP, TCP, send" 2>/dev/null; then
    echo "[ERROR] scapy 미설치 또는 임포트 실패"
    echo "        apt-get install -y python3-scapy  를 먼저 실행하세요."
    exit 1
fi

# NET_RAW 권한 확인 (raw socket 필요)
if ! python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.close()
except PermissionError:
    sys.exit(1)
" 2>/dev/null; then
    echo "[ERROR] NET_RAW 권한 없음"
    echo "        docker-compose.yml 의 cap_add: [NET_RAW] 설정을 확인하세요."
    exit 1
fi

python3 /ddos_simulate.py \
    --target   "$TARGET"    \
    --port     "$PORT"      \
    --attackers "$ATTACKERS" \
    --duration "$DURATION"
