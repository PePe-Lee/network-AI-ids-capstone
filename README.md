# HY-NIDS 캡스톤 프로젝트

[**최신 오프라인 데모와 실행 안내 보기**](hy-nids/README.md)

기존 IDS에 AI 모델을 OR로 결합했을 때의 추가 탐지와 오탐을 비교했습니다. 최신 폴더에서는 Docker 없이 결과 화면을 열거나, 정상 합성 PCAP으로 32특성 추출과 고정 OCSVM 점수 계산을 다시 확인할 수 있습니다.

아래는 기존 초기 연구 설명입니다.

---

# network-AI-ids-capstone
AI-based Network Intrusion Detection System using CICIDS2017 dataset. This project implements flow-based traffic analysis, multi-class attack classification, and semi-real-time detection pipeline.
# AI-Based Network Intrusion Detection System

## Overview
This project implements a machine learning-based IDS using CICIDS2017 dataset.

## Features
- Flow-based traffic analysis
- Multi-class attack classification (DoS/DDoS, PortScan,Brute Force, Web Attack, Bot)
- semi-real-time detection pipeline (tcpdump + CICFlowMeter)

## Model
- Multi-class classification model
- Full feature-based training
- Web attack label aggregation for improved accuracy

## Dataset
- CICIDS2017

## Result
- High accuracy for DoS/DDoS and PortScan
- Web Attack improved after label aggregation

## Future Work
- Integration with LLM for payload analysis
- Real-time dashboard

