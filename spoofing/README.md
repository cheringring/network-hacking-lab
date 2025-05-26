# ARP 스푸핑 (Spoofing) 실습

## 실습 문제

### 실습 선정 이유
ARP 스푸핑은 로컬 네트워크에서 중간자 공격(Man-in-the-Middle)을 수행하기 위한 기본적인 기술입니다. 이 실습에서는 기존의 단순한 ARP 스푸핑 도구 사용법을 넘어서, Python과 Scapy 라이브러리를 활용하여 맞춤형 ARP 스푸핑 도구를 직접 개발하고 실행합니다. 이를 통해 네트워크 프로토콜의 취약점을 깊이 이해하고, 스크립팅 능력을 향상시키며, 실제 공격 및 방어 메커니즘을 체험할 수 있습니다.

### 필요한 사전 지식
- ARP(Address Resolution Protocol) 프로토콜의 작동 원리
- MAC 주소와 IP 주소의 관계
- 로컬 네트워크 통신 방식
- Python 프로그래밍 기초
- 패킷 구조와 네트워크 스택의 이해

## 실습 목표
1. ARP 프로토콜의 취약점 이해 및 실습
2. Scapy를 이용한 맞춤형 ARP 스푸핑 도구 개발
3. 중간자 공격을 통한 네트워크 트래픽 감청
4. ARP 스푸핑 탐지 및 방어 기법 학습

## 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Python 3, Scapy, Wireshark, arpspoof(dsniff 패키지)
- 대상 시스템: Windows/Linux 가상머신 (희생자 역할)

## 실습 준비
1. Kali Linux 가상머신 설치
2. 대상 시스템으로 Windows 또는 Linux 가상머신 설치
3. 가상 네트워크 구성 (NAT 또는 Host-only 네트워크)
4. 필요한 도구 설치 확인:
   ```bash
   sudo apt update
   sudo apt install python3-scapy wireshark-qt dsniff
   ```
5. IP 포워딩 활성화:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

## 실습 내용

### 1. 기본 ARP 스푸핑 (dsniff 도구 사용)

#### ARP 스푸핑 실행
```bash
# 대상 호스트(192.168.56.101)에게 게이트웨이(192.168.56.1)인 척하기
sudo arpspoof -i eth0 -t 192.168.56.101 192.168.56.1

# 동시에 다른 터미널에서 게이트웨이에게 대상 호스트인 척하기
sudo arpspoof -i eth0 -t 192.168.56.1 192.168.56.101
```

#### 트래픽 캡처
```bash
# Wireshark로 트래픽 캡처
sudo wireshark -i eth0 -k
```

### 2. Scapy를 이용한 맞춤형 ARP 스푸핑 도구 개발

#### ARP 스푸핑 스크립트 작성
`arp_spoofer.py` 스크립트를 작성하여 다음 기능을 구현:
- 네트워크 스캔 및 활성 호스트 탐지
- 선택한 대상에 대한 ARP 스푸핑 수행
- 패킷 전달 (IP 포워딩)
- 스푸핑 상태 모니터링 및 로깅

#### 스크립트 실행
```bash
sudo python3 arp_spoofer.py -t 192.168.56.101 -g 192.168.56.1
```

### 3. 고급 ARP 스푸핑 기법

#### 선택적 패킷 조작
`packet_modifier.py` 스크립트를 작성하여 다음 기능을 구현:
- HTTP 트래픽 감지 및 내용 변조
- DNS 응답 위조 (DNS 스푸핑)
- 이미지 교체 또는 JavaScript 삽입

#### 스크립트 실행
```bash
sudo python3 packet_modifier.py -i eth0 -t 192.168.56.101
```

### 4. ARP 스푸핑 탐지 및 방어

#### 탐지 도구 개발
`arp_detector.py` 스크립트를 작성하여 다음 기능을 구현:
- ARP 테이블 모니터링
- 비정상적인 ARP 응답 탐지
- MAC 주소 변경 감지
- 경고 알림 생성

#### 방어 기법 구현
- 정적 ARP 항목 설정
- ARP 스푸핑 방지 도구 사용
- 네트워크 모니터링 시스템 구축

## 실습 결과 분석
1. ARP 스푸핑 공격의 성공 여부 평가
2. 캡처한 트래픽에서 추출한 민감한 정보 목록 작성
3. 패킷 조작 결과 분석 및 스크린샷 제공
4. 탐지 및 방어 도구의 효과 평가
5. 실제 네트워크 환경에서의 위험성 및 대응 방안 논의

## 참고 자료
- [Scapy 공식 문서](https://scapy.readthedocs.io/)
- [ARP 스푸핑 관련 OWASP 가이드](https://owasp.org/www-community/attacks/ARP_Spoofing)
- [Kali Linux 공식 도구 문서](https://www.kali.org/tools/dsniff/)
- [네트워크 보안: 원리와 실습](https://www.amazon.com/Network-Security-Private-Communication-Public/dp/0130460192)
