import time
from collections import defaultdict
from alerting import send_email_alert, send_sms_alert, log_alert

port_scan_activity = defaultdict(list)
syn_flooding_activity = defaultdict(list)
dns_amplification_activity = defaultdict(list)
syn_packets ={}
time_threshold = 10

def detect_port_scan(packet_info):
    source_ip = packet_info.get('source_ip')
    destination_port = packet_info.get('destination_port')

    if source_ip and destination_port:
        current_time = time.time()
        port_scan_activity[source_ip].append((destination_port, current_time))
        
        #Checking for old traffic
        port_scan_activity[source_ip] = [(port, t) for port, t in port_scan_activity[source_ip] if current_time < time_threshold]

        if len(set(port for port, t in port_scan_activity[source_ip])) > 10:
            print(f"Port Scanning Detected: {source_ip} is scanning ports!")

def detect_syn_flooding(packet_info):
    source_ip = packet_info.get('source_ip')
    flags = packet_info.get('flags')

    if source_ip and flags:
        if 'S' in flags and 'A' not in flags:
            current_time = time.time()
            syn_flooding_activity[source_ip].append(current_time)

            syn_flooding_activity[source_ip] = [t for t in syn_flooding_activity[source_ip] if (current_time - t) < time_threshold]

            if len(syn_flooding_activity[source_ip]) > 100:
                print(f"SYN Flood Detected: {source_ip} is sending SYN packets!")

                ip = packet_info.get('source_ip')
                alert_msg = f"SYN Flood Alert: High traffic detected from IP {ip}"
                email_subject = "Intrusion Alert: SYN Flood Detected"
                email_body = f"A SYN flood attack has been detected from IP {ip}. Please investigate immediately."

                # Send alerts
                send_email_alert(email_subject, email_body)
                send_sms_alert(alert_msg) 
                log_alert(alert_msg)

def detect_dns_amplification(packet_info):
    source_ip = packet_info.get('source_ip')
    dns_query = packet_info.get('dns_query')

    if source_ip and dns_query:
        current_time = time.time()
        dns_amplification_activity[source_ip] =[t for t in dns_amplification_activity[source_ip] if (current_time - t) < time_threshold]

        if len(dns_amplification_activity[source_ip]) > 50:
            print(f"DNS Amplification Detected: {source_ip} is sending too many DNS requests!")

    return
