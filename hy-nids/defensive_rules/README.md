# 방어 규칙과 평가 정책

여기에는 프로젝트에서 추가한 Snort·Suricata의 HTTP 탐지 시그니처, Zeek의 추가 이벤트 정책, 선택한 평가 정책의 근거를 담았습니다. 공격을 일으키는 코드가 아니라 캡처를 읽는 엔진의 탐지 쪽 자료입니다.

- Docker 18종의 `refined` 선택 신호는 `docker18-profiles.json`에 있습니다.
- CICIDS2017의 선택 기준과 임계값은 `policies/CICIDS2017/maxF1_policy.json`에 있습니다.
- `policies/CIC-DDoS2019/ddos2019.zeek`는 연구의 관련 Zeek 탐지 소스 일부이며 최종 경보 조합을 혼자 재현하는 설정은 아닙니다.
- 외부 규칙 피드, 엔진 이미지 및 각 공급자의 기본 설정을 재배포하지 않습니다. 이 폴더의 조각들은 전체 설정을 대체하지 않습니다.
