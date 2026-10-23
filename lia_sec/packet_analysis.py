"""Packet analysis and indicator detection for LIA-Sec."""

# Import the necessary libraries
from scapy.all import (
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    ICMP,
    Raw,
    rdpcap,
)
import ipaddress
from collections import Counter


# ----------------------------------------------------------------------
# Detection thresholds
# Adjust these to fit your network and use case.
# ----------------------------------------------------------------------
DNS_QUERY_THRESHOLD = 100        # alert when DNS queries exceed this
SYN_FLOOD_THRESHOLD = 100        # SYNs per (source, destination) pair
PORT_SCAN_THRESHOLD = 10         # distinct destination ports per source
TCP_RESET_THRESHOLD = 10         # alert at this many TCP resets or more


def analyze_pcap_capture(pcap_file):
    packets = rdpcap(pcap_file)

    ip_pairs = []
    tcp_pairs = []
    udp_pairs = []
    private_ips = []
    dns_queries = []
    icmp_packets = []
    http_requests = []

    # Track TCP connection indicators
    syn_requests = []
    syn_ack_pairs = set()
    rst_pairs = []

    # Track destination ports by source IP
    ports_by_source = {}

    # Analyze each packet
    for packet in packets:
        if IP not in packet:
            continue

        ip = packet[IP]
        ip_pairs.append((ip.src, ip.dst))

        # Extract DNS queries
        if DNS in packet and DNSQR in packet:
            dns_query = packet[DNSQR].qname
            dns_queries.append(
                dns_query.decode(errors="ignore")
            )

        # Identify ICMP packets
        if ICMP in packet:
            icmp_packets.append(packet[ICMP].type)

        # Identify private source IP addresses
        if ipaddress.ip_address(ip.src).is_private:
            private_ips.append(ip.src)

        # Extract TCP ports and connection indicators
        if TCP in packet:
            tcp = packet[TCP]
            tcp_pairs.append((tcp.sport, tcp.dport))

            flags = int(tcp.flags)
            connection = (
                ip.src,
                ip.dst,
                tcp.sport,
                tcp.dport,
            )

            # SYN set, ACK unset: initial TCP connection attempt
            if flags & 0x02 and not flags & 0x10:
                syn_requests.append(connection)

                ports_by_source.setdefault(
                    ip.src, set()
                ).add(tcp.dport)

            # SYN and ACK set: response to a connection attempt
            if flags & 0x12 == 0x12:
                syn_ack_pairs.add((
                    ip.dst,
                    ip.src,
                    tcp.dport,
                    tcp.sport,
                ))

            # Track TCP reset packets
            if flags & 0x04:
                rst_pairs.append(connection)

        # Extract UDP ports
        elif UDP in packet:
            udp = packet[UDP]
            udp_pairs.append((udp.sport, udp.dport))

        # Extract visible HTTP requests
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load

            if payload.startswith((
                b"GET ",
                b"POST ",
                b"PUT ",
                b"DELETE ",
                b"HEAD ",
                b"OPTIONS ",
                b"PATCH ",
            )):
                http_requests.append(
                    payload.decode(errors="ignore")
                )

    # Calculate analysis counts
    unique_private_ips = set(private_ips)
    syn_counts = Counter(
        (src, dst)
        for src, dst, sport, dport in syn_requests
    )

    # Count distinct destination ports per source IP
    source_port_counts = {
        src: len(ports)
        for src, ports in ports_by_source.items()
    }

    result = {
        "packet_count": len(packets),
        "ip_pair_count": len(ip_pairs),
        "ip_pairs": ip_pairs,
        "tcp_pair_count": len(tcp_pairs),
        "tcp_pairs": tcp_pairs,
        "udp_pair_count": len(udp_pairs),
        "udp_pairs": udp_pairs,
        "private_ip_count": len(private_ips),
        "private_ips": private_ips,
        "unique_private_ips": unique_private_ips,
        "unique_private_ip_count": len(unique_private_ips),
        "dns_query_count": len(dns_queries),
        "dns_queries": dns_queries,
        "icmp_packet_count": len(icmp_packets),
        "icmp_packets": icmp_packets,
        "http_request_count": len(http_requests),
        "http_requests": http_requests,
        "syn_request_count": len(syn_requests),
        "syn_requests": syn_requests,
        "syn_ack_response_count": len(syn_ack_pairs),
        "syn_counts_by_connection": dict(syn_counts),
        "destination_port_counts_by_source": source_port_counts,
        "tcp_reset_count": len(rst_pairs),
        "tcp_reset_packets": rst_pairs,
    }

    return result


def detect_suspicious_activity(analysis):
    alerts = []

    # Detect unusually high DNS query volume
    if analysis["dns_query_count"] > DNS_QUERY_THRESHOLD:
        alerts.append({
            "type": "High DNS Query Volume",
            "count": analysis["dns_query_count"],
            "severity": "Review",
        })

    # Flag ICMP traffic for review
    if analysis["icmp_packet_count"] > 0:
        alerts.append({
            "type": "ICMP Traffic Detected",
            "count": analysis["icmp_packet_count"],
            "severity": "Review",
        })

    # Flag visible HTTP requests for review
    if analysis["http_request_count"] > 0:
        alerts.append({
            "type": "HTTP Requests Detected",
            "count": analysis["http_request_count"],
            "severity": "Review",
        })

    # Detect a high volume of initial SYN packets
    for connection, count in analysis[
        "syn_counts_by_connection"
    ].items():
        if count > SYN_FLOOD_THRESHOLD:
            alerts.append({
                "type": "Possible SYN Flood Indicator",
                "source_ip": connection[0],
                "destination_ip": connection[1],
                "syn_count": count,
                "severity": "Review",
            })

    # Detect possible port scanning
    for source_ip, port_count in analysis[
        "destination_port_counts_by_source"
    ].items():
        if port_count >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "Possible Port Scan Indicator",
                "source_ip": source_ip,
                "distinct_destination_ports": port_count,
                "severity": "Review",
            })

    # Flag repeated TCP reset packets for investigation
    if analysis["tcp_reset_count"] >= TCP_RESET_THRESHOLD:
        alerts.append({
            "type": "Repeated TCP Resets",
            "count": analysis["tcp_reset_count"],
            "severity": "Review",
        })

    return alerts
