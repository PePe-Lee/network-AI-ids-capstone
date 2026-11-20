# HY-NIDS: 네트워크 침입탐지 보완 연구와 오프라인 데모

오픈소스 IDS의 경보에 AI 판정을 OR로 결합했을 때, 놓친 공격 구간을 얼마나 더 탐지하고 정상 오탐이 얼마나 늘어나는지 살펴본 캡스톤 프로젝트입니다. 평가 단위는 패킷이 아니라 **IP별 1분 구간**입니다.

## 바로 시작하기

### 설치 없이 저장 결과 보기

1. GitHub에서 **Code → Download ZIP**을 선택해 압축을 풉니다.
2. 이 폴더의 `dashboard.html`을 Chrome 또는 Edge에서 엽니다.
3. CICIDS2017, CIC-DDoS2019, Docker 18종과 모델을 바꿔 IDS 단독, AI 단독, OR 결합의 지표를 비교합니다.

GitHub의 파일 미리보기 대신 내려받은 HTML을 브라우저에서 직접 여세요. 인터넷 연결 없이 동작하며 서버 기동이나 새 분석은 하지 않습니다.

### 정상 샘플 다시 분석하기

이 폴더에서 Python 3.10 이상으로 다음을 실행합니다. 외부 Python 패키지는 필요 없습니다.

```sh
python check_extract.py
```

예상 결과는 **1,320패킷, 120 TCP 흐름, 32특성의 IP·분 구간 60개**입니다. 샘플은 루프백 HTTP 요청과 응답만 담으며 네트워크로 전송하지 않습니다. 수치 파라미터에서 고정 OCSVM의 점수를 다시 계산해 검증합니다. 저장 IDS 판정으로 OR 결합도 확인하지만 **새 IDS 엔진 경보는 계산하지 않습니다**.

### Docker로 대시보드와 샘플 검증 실행하기

Docker와 Compose v2를 준비하고 이 폴더에서 실행합니다. Windows에서는 Docker Desktop이 준비된 뒤 `start_demo.cmd`를 두 번 클릭해도 됩니다.

```sh
docker compose up -d --build --wait
```

- 대시보드: <http://127.0.0.1:15007/>
- 정상 샘플 검증 로그: <http://127.0.0.1:15007/health>
- 종료: `docker compose down` 또는 Windows의 `stop_demo.cmd`

첫 빌드는 기반 이미지를 내려받을 수 있습니다. 웹 포트는 로컬 PC에만 바인딩되고 서비스는 읽기 전용입니다. 공개 서비스로 배포하도록 구성하지 않았습니다.

## 파일 구성

| 위치 | 내용 |
| --- | --- |
| `sample/` | 정상 합성 PCAP, 32개 특성 순서와 참조 입력, 고정 OCSVM 수치와 저장 예측 |
| `dashboard_src/` | 대시보드 HTML·CSS·JS와 집계 데이터. `python dashboard_src/build_portable_reference.py --out dashboard.html`로 재생성 |
| `results/` | 데이터셋·공격 범주별 저장 평가표, 모델 시간·자원 CSV, Docker ROC |
| `defensive_rules/` | 프로젝트 추가 HTTP 탐지 규칙, 평가 정책과 경보 선택 자료. 전체 룰 피드나 실시간 실행 스택은 아님 |

## 평가 자료와 해석

- [CICIDS2017 공식 배포처](https://www.unb.ca/cic/datasets/ids-2017.html): 최종 결과의 IDS는 선택한 23개 신호를 OR 결합한 기준선입니다. 라벨을 참고해 조정한 정책이므로 회고적 비교입니다.
- [CIC-DDoS2019 공식 배포처](https://www.unb.ca/cic/datasets/ddos-2019.html): 최종 결과의 IDS는 Zeek 단독 기준선입니다. 입력 구성별 민감도 결과는 분리되어 있습니다.
- Docker 18종: 캡처별 3분할 OOF 비교입니다. 시나리오 라벨은 공격 의도 구간이며 공격이 실제 성공했다는 의미는 아닙니다.
- 정상 합성 데모에서의 경보 수는 연구 데이터의 오탐률이나 실제 운영 환경 성능을 뜻하지 않습니다. 원본 데이터셋 전체, 실습 웹·DB, 전체 학습 산출물, 공격 생성·재생 도구 및 외부 룰 피드는 이 공개본에 포함하지 않았습니다.

기존 저장소의 초기 노트북과 파일은 이 폴더 밖에 별도로 남아 있으며 이 안내의 실행 대상이 아닙니다.

용량이 큰 결과표는 무손실 gzip으로 압축했습니다. Windows에서도 Python 표준 도구로 `python -m gzip -d results/파일명.csv.gz`를 실행하면 CSV를 읽을 수 있습니다.
