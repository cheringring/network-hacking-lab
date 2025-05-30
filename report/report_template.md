# 네트워크 해킹 실습 보고서

**학과:**  
**학번:**  
**이름:**  
**제출일:** 2025년 5월 27일

## 목차

1. [실습 1: 네트워크 목록화 (Enumeration)](#실습-1-네트워크-목록화-enumeration)
2. [실습 2: 네트워크 스니핑 (Sniffing)](#실습-2-네트워크-스니핑-sniffing)
3. [실습 3: ARP 스푸핑 (Spoofing)](#실습-3-arp-스푸핑-spoofing)
4. [결론 및 보안 대책](#결론-및-보안-대책)
5. [참고 문헌](#참고-문헌)

---

## 실습 1: 네트워크 목록화 (Enumeration)

### 1. 실습 문제

#### 실습 선정 이유
네트워크 목록화(Enumeration)는 모든 네트워크 보안 평가의 첫 단계입니다. 이 실습에서는 일반적인 Nmap 스캔을 넘어서, 실제 보안 전문가들이 사용하는 고급 스캐닝 기법과 Masscan이라는 고성능 스캐너를 활용하는 방법을 학습했습니다. 이러한 고급 기술은 대규모 네트워크 환경에서 효율적인 취약점 분석을 가능하게 합니다.

#### 필요한 사전 지식
- 기본적인 네트워크 개념 (IP 주소, 포트, 프로토콜)
- TCP/IP 스택의 기본 이해
- 리눅스 명령어 기초
- 네트워크 서비스의 종류와 기능

### 2. 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Nmap, Masscan, Python 3
- 가상 머신 구성: VirtualBox 7.0, NAT 네트워크 설정

### 3. 실습 내용

#### 고급 Nmap 스캐닝 기법 실습

**스텔스 스캔 (SYN 스캔) 실행 및 결과**

```bash
sudo nmap -sS -p 1-1000 192.168.56.101
```

[스크린샷 1: SYN 스캔 결과]

**서비스 및 버전 탐지 실행 및 결과**

```bash
sudo nmap -sV -p 1-1000 192.168.56.101
```

[스크린샷 2: 서비스 버전 탐지 결과]

**OS 탐지 실행 및 결과**

```bash
sudo nmap -O 192.168.56.101
```

[스크린샷 3: OS 탐지 결과]

**스크립트 스캔 실행 및 결과**

```bash
sudo nmap -sC 192.168.56.101
```

[스크린샷 4: 스크립트 스캔 결과]

**종합 스캔 실행 및 결과**

```bash
sudo nmap -sS -sV -O -A 192.168.56.101
```

[스크린샷 5: 종합 스캔 결과]

#### Masscan을 이용한 대규모 네트워크 스캐닝

**Masscan 설치 및 기본 스캔**

```bash
sudo apt-get update
sudo apt-get install masscan
sudo masscan -p 1-65535 192.168.56.0/24 --rate=1000
```

[스크린샷 6: Masscan 설치 및 실행]

**결과 저장 및 분석**

```bash
sudo masscan -p 1-65535 192.168.56.0/24 --rate=1000 -oX scan_results.xml
python3 analyze_scan.py scan_results.xml
```

[스크린샷 7: Masscan 결과 저장]
[스크린샷 8: 분석 스크립트 실행 결과]

#### 스캔 결과 시각화

[스크린샷 9: 네트워크 토폴로지 시각화]
[스크린샷 10: 서비스 분포 그래프]
[스크린샷 11: 포트 분포 그래프]

### 4. 실습 결과 분석

- 발견된 호스트 및 서비스 목록
- 각 서비스의 버전 정보와 알려진 취약점
- 네트워크 토폴로지 분석
- 발견된 취약점에 대한 대응 방안

---

## 실습 2: 네트워크 스니핑 (Sniffing)

### 1. 실습 문제

#### 실습 선정 이유
네트워크 스니핑은 네트워크 상에서 전송되는 데이터 패킷을 캡처하고 분석하는 기술로, 네트워크 보안 분야에서 중요한 위치를 차지합니다. 이 실습에서는 단순한 패킷 캡처를 넘어서 고급 필터링 기법과 프로토콜 분석, 그리고 실시간 트래픽 모니터링 기술을 학습했습니다. 이러한 기술은 네트워크 문제 해결, 보안 감사, 그리고 침입 탐지에 필수적인 요소입니다.

#### 필요한 사전 지식
- TCP/IP 네트워크 프로토콜 스택의 이해
- OSI 7계층 모델
- 주요 네트워크 프로토콜 (HTTP, HTTPS, DNS, FTP 등)
- 패킷 구조와 헤더 정보
- 기본적인 리눅스 명령어

### 2. 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Wireshark, Ettercap, Python 3, Scapy
- 가상 머신 구성: VirtualBox 7.0, NAT 네트워크 설정

### 3. 실습 내용

#### Wireshark를 이용한 고급 패킷 분석

**실시간 패킷 캡처 및 필터링**

```bash
sudo wireshark
```

[스크린샷 12: Wireshark 실행 및 인터페이스 선택]
[스크린샷 13: 캡처 필터 설정]
[스크린샷 14: 패킷 캡처 결과]

**고급 디스플레이 필터 사용**

[스크린샷 15: HTTP 트래픽 필터링]
[스크린샷 16: 특정 IP 주소 필터링]
[스크린샷 17: 특정 포트 필터링]
[스크린샷 18: HTTP POST 요청 필터링]

**프로토콜 분석**

[스크린샷 19: HTTP 세션 추적]
[스크린샷 20: TCP 스트림 분석]
[스크린샷 21: DNS 쿼리 분석]

#### Ettercap을 이용한 중간자 공격 스니핑

**ARP 스푸핑 설정 및 실행**

```bash
sudo ettercap -G
```

[스크린샷 22: Ettercap 실행]
[스크린샷 23: 호스트 검색 결과]
[스크린샷 24: ARP 스푸핑 설정]
[스크린샷 25: ARP 스푸핑 실행 중]

**패스워드 및 민감 정보 캡처**

[스크린샷 26: 플러그인 활성화]
[스크린샷 27: 캡처된 패스워드 정보]

#### Python과 Scapy를 이용한 맞춤형 패킷 분석

**맞춤형 패킷 스니퍼 실행**

```bash
sudo python3 packet_sniffer.py -i eth0
```

[스크린샷 28: 패킷 스니퍼 실행]
[스크린샷 29: HTTP 트래픽 캡처]
[스크린샷 30: DNS 쿼리 캡처]
[스크린샷 31: FTP 인증 정보 캡처]

### 4. 실습 결과 분석

- 캡처한 패킷에서 발견된 프로토콜 분포 분석
- 암호화되지 않은 통신에서 추출한 민감한 정보 목록
- 네트워크 트래픽 패턴 분석 및 이상 징후 탐지
- 스니핑 방지를 위한 보안 대책 제안

---

## 실습 3: ARP 스푸핑 (Spoofing)

### 1. 실습 문제

#### 실습 선정 이유
ARP 스푸핑은 로컬 네트워크에서 중간자 공격(Man-in-the-Middle)을 수행하기 위한 기본적인 기술입니다. 이 실습에서는 기존의 단순한 ARP 스푸핑 도구 사용법을 넘어서, Python과 Scapy 라이브러리를 활용하여 맞춤형 ARP 스푸핑 도구를 직접 개발하고 실행했습니다. 이를 통해 네트워크 프로토콜의 취약점을 깊이 이해하고, 스크립팅 능력을 향상시키며, 실제 공격 및 방어 메커니즘을 체험할 수 있었습니다.

#### 필요한 사전 지식
- ARP(Address Resolution Protocol) 프로토콜의 작동 원리
- MAC 주소와 IP 주소의 관계
- 로컬 네트워크 통신 방식
- Python 프로그래밍 기초
- 패킷 구조와 네트워크 스택의 이해

### 2. 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Python 3, Scapy, Wireshark, arpspoof(dsniff 패키지)
- 대상 시스템: Windows 10 가상머신 (희생자 역할)
- 가상 머신 구성: VirtualBox 7.0, NAT 네트워크 설정

### 3. 실습 내용

#### 기본 ARP 스푸핑 (dsniff 도구 사용)

**ARP 스푸핑 실행**

```bash
# 대상 호스트(192.168.56.101)에게 게이트웨이(192.168.56.1)인 척하기
sudo arpspoof -i eth0 -t 192.168.56.101 192.168.56.1

# 동시에 다른 터미널에서 게이트웨이에게 대상 호스트인 척하기
sudo arpspoof -i eth0 -t 192.168.56.1 192.168.56.101
```

[스크린샷 32: arpspoof 실행]
[스크린샷 33: 두 번째 터미널에서 arpspoof 실행]

**트래픽 캡처**

```bash
sudo wireshark -i eth0 -k
```

[스크린샷 34: Wireshark로 트래픽 캡처]

#### Scapy를 이용한 맞춤형 ARP 스푸핑 도구 개발

**ARP 스푸핑 스크립트 실행**

```bash
sudo python3 arp_spoofer.py -t 192.168.56.101 -g 192.168.56.1
```

[스크린샷 35: 맞춤형 ARP 스푸퍼 실행]
[스크린샷 36: 네트워크 스캔 결과]
[스크린샷 37: ARP 스푸핑 진행 중]
[스크린샷 38: 희생자 시스템의 ARP 테이블 변경 확인]

#### 고급 ARP 스푸핑 기법

**선택적 패킷 조작**

```bash
sudo python3 packet_modifier.py -i eth0 -t 192.168.56.101
```

[스크린샷 39: 패킷 조작 스크립트 실행]
[스크린샷 40: HTTP 트래픽 변조 결과]
[스크린샷 41: DNS 응답 위조 결과]
[스크린샷 42: 희생자 브라우저에서 변조된 웹페이지]

#### ARP 스푸핑 탐지 및 방어

**탐지 도구 개발 및 실행**

```bash
sudo python3 arp_detector.py
```

[스크린샷 43: ARP 탐지 도구 실행]
[스크린샷 44: 비정상적인 ARP 응답 탐지]
[스크린샷 45: 경고 알림 생성]

**방어 기법 구현**

```bash
# 정적 ARP 항목 설정
sudo arp -s 192.168.56.1 00:11:22:33:44:55
```

[스크린샷 46: 정적 ARP 항목 설정]
[스크린샷 47: ARP 스푸핑 방지 도구 실행]

### 4. 실습 결과 분석

- ARP 스푸핑 공격의 성공 여부 평가
- 캡처한 트래픽에서 추출한 민감한 정보 목록
- 패킷 조작 결과 분석
- 탐지 및 방어 도구의 효과 평가
- 실제 네트워크 환경에서의 위험성 및 대응 방안 논의

---

## 결론 및 보안 대책

### 발견된 취약점 요약
- 암호화되지 않은 프로토콜 사용 (HTTP, FTP, Telnet 등)
- 약한 인증 메커니즘
- ARP 프로토콜의 근본적인 취약점
- 네트워크 트래픽 모니터링 부재

### 권장 보안 대책
1. **암호화 통신 사용**
   - HTTP 대신 HTTPS 사용
   - FTP 대신 SFTP 또는 FTPS 사용
   - Telnet 대신 SSH 사용

2. **네트워크 모니터링 강화**
   - IDS/IPS 시스템 도입
   - 네트워크 트래픽 분석 도구 사용
   - 비정상 트래픽 패턴 탐지 시스템 구축

3. **ARP 스푸핑 방어**
   - 정적 ARP 테이블 사용
   - ARP Watch 같은 모니터링 도구 사용
   - VLAN 분리 및 네트워크 세그먼테이션

4. **인증 및 접근 제어 강화**
   - 강력한 패스워드 정책 수립
   - 다중 인증(MFA) 도입
   - 최소 권한 원칙 적용

### 학습 성과
이번 실습을 통해 네트워크 보안의 중요성과 실제 해킹 기법의 작동 원리를 깊이 이해할 수 있었습니다. 특히 맞춤형 도구 개발을 통해 스크립팅 능력을 향상시키고, 실제 공격 및 방어 메커니즘을 체험함으로써 보안 전문가로서의 역량을 키울 수 있었습니다.

---

## 참고 문헌

1. Lyon, G. (2009). Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning. Nmap Project.
2. Sanders, C. (2017). Practical Packet Analysis: Using Wireshark to Solve Real-World Network Problems. No Starch Press.
3. Bullock, J., & Parker, J. (2017). Wireshark for Security Professionals: Using Wireshark and the Metasploit Framework. Wiley.
4. Offensive Security. (2023). Kali Linux Documentation. https://www.kali.org/docs/
5. Scapy Documentation. https://scapy.readthedocs.io/
6. OWASP. (2023). OWASP Web Security Testing Guide. https://owasp.org/www-project-web-security-testing-guide/
