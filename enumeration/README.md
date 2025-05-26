# 네트워크 목록화 (Enumeration) 실습

## 실습 문제

### 실습 선정 이유
네트워크 목록화(Enumeration)는 모든 네트워크 보안 평가의 첫 단계입니다. 이 실습은 일반적인 Nmap 스캔을 넘어서, 실제 보안 전문가들이 사용하는 고급 스캐닝 기법과 Masscan이라는 고성능 스캐너를 활용하는 방법을 배우게 됩니다. 이러한 고급 기술은 대규모 네트워크 환경에서 효율적인 취약점 분석을 가능하게 합니다.

### 필요한 사전 지식
- 기본적인 네트워크 개념 (IP 주소, 포트, 프로토콜)
- TCP/IP 스택의 기본 이해
- 리눅스 명령어 기초
- 네트워크 서비스의 종류와 기능

## 실습 목표
1. Nmap의 고급 스캐닝 기법 습득
2. Masscan을 이용한 대규모 네트워크 스캐닝 수행
3. 스캔 결과를 분석하여 네트워크 토폴로지 및 취약점 파악
4. 스캔 탐지 회피 기법 학습

## 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Nmap, Masscan, Python 3

## 실습 준비
1. Kali Linux 가상머신 설치
2. 대상 시스템으로 Metasploitable2 또는 DVWA 가상머신 설치
3. 가상 네트워크 구성 (NAT 또는 Host-only 네트워크)

## 실습 내용

### 1. 고급 Nmap 스캐닝 기법

#### 스텔스 스캔 (SYN 스캔)
```bash
sudo nmap -sS -p 1-1000 [대상IP]
```

#### 서비스 및 버전 탐지
```bash
sudo nmap -sV -p 1-1000 [대상IP]
```

#### OS 탐지
```bash
sudo nmap -O [대상IP]
```

#### 스크립트 스캔
```bash
sudo nmap -sC [대상IP]
```

#### 종합 스캔
```bash
sudo nmap -sS -sV -O -A [대상IP]
```

### 2. Masscan을 이용한 대규모 네트워크 스캐닝

#### Masscan 설치 (이미 Kali에 설치되어 있을 수 있음)
```bash
sudo apt-get update
sudo apt-get install masscan
```

#### 기본 스캔
```bash
sudo masscan -p 1-65535 [대상네트워크/24] --rate=1000
```

#### 결과 저장
```bash
sudo masscan -p 1-65535 [대상네트워크/24] --rate=1000 -oX scan_results.xml
```

### 3. 스캔 결과 분석 및 시각화

#### Python을 이용한 결과 분석 스크립트 실행
```bash
python3 analyze_scan.py scan_results.xml
```

## 실습 결과 분석
1. 발견된 호스트 및 서비스 목록 작성
2. 각 서비스의 버전 정보와 알려진 취약점 확인
3. 네트워크 토폴로지 맵 작성
4. 발견된 취약점에 대한 대응 방안 제시

## 참고 자료
- [Nmap 공식 문서](https://nmap.org/book/man.html)
- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
- [OWASP 정보 수집 가이드](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README.html)
