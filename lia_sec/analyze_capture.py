"""Run the complete LIA-Sec PCAP analysis workflow."""

import sys
from pathlib import Path

from lia_sec.packet_analysis import (
    analyze_pcap_capture,
    detect_suspicious_activity,
)
from lia_sec.ai_analysis import analyze_with_llama


def analyze_capture(pcap_file):
    """Analyze a PCAP, detect indicators, and generate an AI report."""

    capture_path = Path(pcap_file)

    if not capture_path.is_file():
        raise FileNotFoundError(
            f"PCAP capture not found: {capture_path}"
        )

    # Step 1: Analyze captured network traffic.
    analysis = analyze_pcap_capture(str(capture_path))

    # Step 2: Detect indicators for investigation.
    alerts = detect_suspicious_activity(analysis)

    # Step 3: Generate an AI explanation without losing
    # the packet analysis if the local AI service fails.
    try:
        ai_report = analyze_with_llama(analysis, alerts)
        ai_status = "completed"
    except Exception as exc:
        ai_report = (
            "AI analysis unavailable. "
            f"Reason: {type(exc).__name__}: {exc}"
        )
        ai_status = "unavailable"

    # Step 4: Combine the results into one report.
    return {
        "capture_file": str(capture_path),
        "packet_summary": {
            "packet_count": analysis["packet_count"],
            "dns_query_count": analysis["dns_query_count"],
            "icmp_packet_count": analysis["icmp_packet_count"],
            "http_request_count": analysis["http_request_count"],
        },
        "security_alerts": alerts,
        "ai_status": ai_status,
        "ai_report": ai_report,
    }


def print_report(report):
    """Display the unified LIA-Sec report."""

    print("\n========== LIA-Sec Report ==========")
    print(f"\nCapture: {report['capture_file']}")

    print("\nPACKET SUMMARY:")
    for metric, value in report["packet_summary"].items():
        print(f"{metric}: {value}")

    print("\nSECURITY ALERTS:")
    if report["security_alerts"]:
        for alert in report["security_alerts"]:
            print(alert)
    else:
        print("No alerts detected.")

    print(f"\nAI STATUS: {report['ai_status']}")
    print("\nAI SECURITY ANALYSIS:")
    print(report["ai_report"])

    print("\n========== End of Report ==========")


if __name__ == "__main__":
    # Usage: python -m lia_sec.analyze_capture path/to/capture.pcapng
    if len(sys.argv) != 2:
        print("Usage: python -m lia_sec.analyze_capture <capture.pcap>")
        sys.exit(1)

    print_report(analyze_capture(sys.argv[1]))
