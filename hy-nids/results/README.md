# 저장 결과표

- `*-summary.csv.gz`: 데이터셋 단위 기존 저장 평가표입니다. 분기와 평가 범위에 따라 표본이 다릅니다.
- `*-by-family.csv`: 공격 분류별 탐지 결과입니다.
- `threshold-sensitivity-selected-models.csv`: 2017 OCSVM, 2019 Deep SVDD·HistGB의 저장 임계값별 결과 일부입니다. 시드는 20261117을 사용했습니다.
- `normal-fraction-selected-models.csv`: 같은 모델의 정상 트래픽 비율 변화에 따른 결과입니다. 모델·임계값을 다시 학습하지 않았습니다.
- `load-loss-summary.csv`: 별도 부하 진단에서 관측한 패킷 손실과 IP·분 단위 탐지 결과입니다. 패킷 손실과 미탐을 같은 수치로 해석하지 않습니다.
- `model-resource-comparison.csv`: 별도의 모델 14종 처리 성능과 자원 벤치마크입니다. 인프라 전체의 처리량을 뜻하지 않습니다.
