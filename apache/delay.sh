#!/bin/bash
# 네트워크 지연 추가 스크립트 (VM 환경 시뮬레이션)
DELAY=${NETWORK_DELAY_MS:-20}

echo "[delay.sh] eth0에 ${DELAY}ms 지연 추가 중..."

if tc qdisc add dev eth0 root netem \
     delay ${DELAY}ms 10ms 25% \
     loss 0.1% 2>/dev/null; then
    echo "[delay.sh] 지연 설정 완료 (${DELAY}ms +/-10ms, 패킷 손실 0.1%)"
else
    echo "[delay.sh] 경고: tc 네트워크 지연 설정 실패 - 계속 진행"
fi

/usr/local/bin/tcpdump.sh &
echo "[delay.sh] Apache 시작..."
exec apache2-foreground
