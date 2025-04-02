import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# Définition du sous-réseau à scanner
SUBNET = '192.168.1.0/24'
# Message envoyé pour tester la présence des hôtes
MESSAGE = 'boom'

class IPHeader:
    """Représente un en-tête de paquet IP."""
    def __init__(self, raw_data):
        header = struct.unpack('<BBHHHBBH4s4s', raw_data)
        self.version = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]  # Type de service
        self.total_length = header[2]  # Longueur totale du paquet
        self.identification = header[3]  # Identifiant du paquet
        self.fragment_offset = header[4]  # Fragment offset
        self.ttl = header[5]  # Time To Live
        self.protocol = header[6]  # Protocole utilisé (ICMP, TCP, etc.)
        self.checksum = header[7]  # Somme de contrôle
        self.source_address = socket.inet_ntoa(header[8])  # Adresse IP source
        self.destination_address = socket.inet_ntoa(header[9])  # Adresse IP destination

class ICMPHeader:
    """Représente un en-tête ICMP."""
    def __init__(self, raw_data):
        header = struct.unpack('<BBHHH', raw_data)
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.packet_id = header[3]
        self.sequence = header[4]


def send_probe_packets():
    """Envoie des paquets UDP à chaque hôte du sous-réseau pour déclencher une réponse ICMP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf-8'), (str(ip), 65212))


class NetworkScanner:
    """Classe permettant de scanner un réseau via ICMP."""
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff_packets(self):
        """Écoute les paquets ICMP pour identifier les hôtes actifs."""
        active_hosts = set([f'{self.host} *'])
        try:
            while True:
                raw_packet = self.socket.recvfrom(65535)[0]
                ip_header = IPHeader(raw_packet[0:20])
                
                if ip_header.protocol == 1:  # ICMP
                    icmp_offset = ip_header.ihl * 4
                    icmp_packet = raw_packet[icmp_offset:icmp_offset + 8]
                    icmp_header = ICMPHeader(icmp_packet)
                    
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.source_address) in ipaddress.IPv4Network(SUBNET):
                            target_ip = str(ip_header.source_address)
                            if target_ip != self.host and target_ip not in active_hosts:
                                active_hosts.add(target_ip)
                                print(f'Hôte détecté: {target_ip}')
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            if active_hosts:
                print(f'\n\nRésumé: Hôtes actifs sur {SUBNET}')
                for host in sorted(active_hosts):
                    print(f'{host}')
            sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        local_host = sys.argv[1]
    else:
        local_host = '192.168.1.24'

    scanner = NetworkScanner(local_host)
    time.sleep(5)
    thread = threading.Thread(target=send_probe_packets)
    thread.start()
    scanner.sniff_packets()
