from scapy.all import sniff, IP, TCP, UDP, DNS, Ether
from scapy.layers.http import HTTPRequest
from detection_rules import detect_port_scan, detect_dns_amplification, detect_syn_flooding
from SYN_flooding_test import simulate_syn_flood

def packet_summary(packet):
    packet_info = packet_analysis(packet)
    if packet_info:
        detect_port_scan(packet_info)
        detect_syn_flooding(packet_info)
        detect_dns_amplification(packet_info)
        print(f"Packet Info: {packet_info}")

def packet_capture():
    print ("Beginning Packet Capture:")
    sniff(prn = packet_summary, count = 10)

def packet_analysis(packet):
    if packet is None:
        return None 
    
    packet_info = {}

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        packet_info['source_ip'] = ip_layer.src
        packet_info['destination_ip'] = ip_layer.dst
        packet_info['protocol'] = ip_layer.proto

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        packet_info['source_port'] = tcp_layer.sport
        packet_info['destination_port'] = tcp_layer.dport   
        packet_info['flags'] = tcp_layer.flags

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        packet_info['source_port'] = udp_layer.sport
        packet_info['destination_port'] = udp_layer.dport

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        # Add a check to see if `qname` exists before accessing it
        if hasattr(dns_layer, 'qd') and dns_layer.qd is not None:
            packet_info['dns_query'] = dns_layer.qd.qname.decode('utf-8', errors='ignore')  # Handle decoding safely
        else:
            packet_info['dns_query'] = None  # No DNS query found

    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        packet_info['host'] = http_layer.Host.decode
        packet_info['url'] = http_layer.Path.decode
        packet_info['method'] = http_layer.Method.decode
    
    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        packet_info['source_port'] = ether_layer.sport
        packet_info['destination_port'] = ether_layer.dport

    return packet_info

if __name__ == "__main__":
    packet_capture()
