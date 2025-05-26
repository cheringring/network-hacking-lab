# 네트워크 스니핑 (Sniffing) 실습

## 실습 문제

### 실습 선정 이유
네트워크 스니핑은 네트워크 상에서 전송되는 데이터 패킷을 캡처하고 분석하는 기술로, 네트워크 보안 분야에서 중요한 위치를 차지합니다. 이 실습에서는 단순한 패킷 캡처를 넘어서 고급 필터링 기법과 프로토콜 분석, 그리고 실시간 트래픽 모니터링 기술을 학습합니다. 이러한 기술은 네트워크 문제 해결, 보안 감사, 그리고 침입 탐지에 필수적인 요소입니다.

### 필요한 사전 지식
- TCP/IP 네트워크 프로토콜 스택의 이해
- OSI 7계층 모델
- 주요 네트워크 프로토콜 (HTTP, HTTPS, DNS, FTP 등)
- 패킷 구조와 헤더 정보
- 기본적인 리눅스 명령어

## 실습 목표
1. Wireshark를 이용한 고급 패킷 캡처 및 분석 기법 습득
2. Ettercap을 활용한 중간자 공격 환경에서의 패킷 스니핑
3. 암호화되지 않은 프로토콜에서 민감한 정보 추출
4. Python과 Scapy를 이용한 맞춤형 패킷 분석 도구 개발

## 실습 환경
- Kali Linux 2023.1 (가상머신)
- 대상 네트워크: 로컬 가상 네트워크 (192.168.56.0/24)
- 필요 도구: Wireshark, Ettercap, Python 3, Scapy

## 실습 준비
1. Kali Linux 가상머신 설치
2. 대상 시스템으로 Metasploitable2 또는 DVWA 가상머신 설치
3. 가상 네트워크 구성 (NAT 또는 Host-only 네트워크)
4. 필요한 도구 설치 확인:
   ```bash
   sudo apt update
   sudo apt install wireshark-qt ettercap-graphical python3-scapy
   ```

## 실습 내용

### 1. Wireshark를 이용한 고급 패킷 분석

#### 실시간 패킷 캡처
1. Wireshark 실행
   ```bash
   sudo wireshark
   ```
2. 캡처할 네트워크 인터페이스 선택 (일반적으로 eth0 또는 wlan0)
3. 캡처 필터 설정 (예: `host 192.168.56.101`)
4. 패킷 캡처 시작

#### 고급 디스플레이 필터 사용
```
# HTTP 트래픽만 표시
http

# 특정 IP 주소와 관련된 트래픽
ip.addr == 192.168.56.101

# 특정 포트로 향하는 트래픽
tcp.port == 80

# HTTP POST 요청만 표시
http.request.method == "POST"

# 패스워드 필드가 포함된 HTTP 트래픽
http contains "password"
```

#### 프로토콜 분석
1. HTTP 세션 추적: `분석 > HTTP 추적`
2. TCP 스트림 분석: 패킷 우클릭 > `스트림 추적 > TCP 스트림`
3. DNS 쿼리 분석: `dns` 필터 적용

### 2. Ettercap을 이용한 중간자 공격 스니핑

#### ARP 스푸핑 설정
1. Ettercap 실행
   ```bash
   sudo ettercap -G
   ```
2. 스니핑 시작: `스니핑 > 통합 스니핑 시작`
3. 호스트 검색: `호스트 > 호스트 검색`
4. 대상 설정: 
   - 대상 1: 게이트웨이 (일반적으로 192.168.56.1)
   - 대상 2: 희생자 시스템 (예: 192.168.56.101)
5. ARP 스푸핑 시작: `MITM > ARP 스푸핑`

#### 패스워드 및 민감 정보 캡처
1. 플러그인 활성화: `플러그인 > 플러그인 관리`
2. 유용한 플러그인:
   - `password_collector`: 다양한 프로토콜에서 패스워드 수집
   - `dns_spoof`: DNS 응답 위조
   - `sslstrip`: HTTPS 연결 다운그레이드 시도

### 3. Python과 Scapy를 이용한 맞춤형 패킷 분석

#### 기본 패킷 스니퍼 구현
```python
from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP {ip_src}:{sport} -> {ip_dst}:{dport}")
            
            # HTTP 트래픽 분석
            if dport == 80 or sport == 80:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    if "POST" in payload or "GET" in payload:
                        print(f"HTTP: {payload[:100]}...")
        
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"UDP {ip_src}:{sport} -> {ip_dst}:{dport}")
            
            # DNS 트래픽 분석
            if dport == 53 or sport == 53:
                if packet.haslayer(DNS):
                    if packet.haslayer(DNSQR):
                        qname = packet[DNSQR].qname.decode('utf-8')
                        print(f"DNS Query: {qname}")

# 패킷 캡처 시작
sniff(iface="eth0", prn=packet_callback, store=0, count=100)
```

#### 맞춤형 HTTP 세션 추출기 구현
```python
from scapy.all import *
import re

# HTTP 세션 추적을 위한 딕셔너리
sessions = {}

def extract_http_info(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', 'ignore')
        
        # HTTP 요청 분석
        if "GET " in payload or "POST " in payload:
            # 세션 키 생성 (IP:PORT 쌍)
            session_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            
            # HTTP 메서드 추출
            method_match = re.search(r'(GET|POST|PUT|DELETE) (.*?) HTTP', payload)
            if method_match:
                method = method_match.group(1)
                path = method_match.group(2)
                
                # 호스트 추출
                host_match = re.search(r'Host: (.*?)\r\n', payload)
                host = host_match.group(1) if host_match else "Unknown"
                
                # 세션 정보 저장
                sessions[session_key] = {
                    'method': method,
                    'host': host,
                    'path': path,
                    'request': payload[:100] + "..." if len(payload) > 100 else payload,
                    'response': None
                }
                
                print(f"[+] HTTP Request: {method} {host}{path}")
        
        # HTTP 응답 분석
        elif "HTTP/" in payload and "200 OK" in payload:
            # 응답에 대한 세션 키 찾기 (방향 반대)
            session_key = f"{packet[IP].dst}:{packet[TCP].dport}-{packet[IP].src}:{packet[TCP].sport}"
            
            if session_key in sessions:
                # 세션에 응답 추가
                sessions[session_key]['response'] = payload[:100] + "..." if len(payload) > 100 else payload
                print(f"[+] HTTP Response for: {sessions[session_key]['method']} {sessions[session_key]['host']}{sessions[session_key]['path']}")

# 패킷 캡처 시작
print("[*] HTTP 세션 추출기 시작...")
sniff(iface="eth0", prn=extract_http_info, store=0, filter="tcp port 80", count=100)

# 결과 출력
print("\n[*] 캡처된 HTTP 세션:")
for key, session in sessions.items():
    print(f"\n{'='*50}")
    print(f"세션: {key}")
    print(f"요청: {session['method']} {session['host']}{session['path']}")
    print(f"요청 데이터: {session['request']}")
    
    if session['response']:
        print(f"응답 데이터: {session['response']}")
    else:
        print("응답 데이터: 캡처되지 않음")
    print(f"{'='*50}")
```

## 실습 결과 분석
1. 캡처한 패킷에서 발견된 프로토콜 분포 분석
2. 암호화되지 않은 통신에서 추출한 민감한 정보 목록 작성
3. 네트워크 트래픽 패턴 분석 및 이상 징후 탐지
4. 스니핑 방지를 위한 보안 대책 제안

## 참고 자료
- [Wireshark 공식 문서](https://www.wireshark.org/docs/)
- [Ettercap 공식 문서](https://www.ettercap-project.org/docs/)
- [Scapy 공식 문서](https://scapy.readthedocs.io/)
- [OWASP 스니핑 공격 가이드](https://owasp.org/www-community/attacks/Sniffing_attack)
