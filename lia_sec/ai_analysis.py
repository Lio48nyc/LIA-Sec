"""AI-assisted interpretation of LIA-Sec packet analysis results."""

import os

# Import the Ollama package
import ollama


# Override with an environment variable, for example:
#   LIA_MODEL=llama3.1:8b python -m lia_sec.analyze_capture capture.pcap
MODEL = os.environ.get("LIA_MODEL", "llama3.2:3b")


# Analyze summarized packet results and security alerts
def analyze_with_llama(analysis, alerts):

    # Keep only the essential packet metrics
    summary = {
        "packet_count": analysis["packet_count"],
        "dns_query_count": analysis["dns_query_count"],
        "icmp_packet_count": analysis["icmp_packet_count"],
        "icmp_packets": analysis["icmp_packets"],
        "http_request_count": analysis["http_request_count"],
    }

    # Create a focused prompt using the supplied evidence
    prompt = f"""
You are LIA-Sec, a cybersecurity analysis assistant.

Analyze ONLY the evidence provided below.

PACKET SUMMARY:
{summary}

DETECTED ALERTS:
{alerts}

RULES:
1. Use only facts explicitly present in the supplied data.
2. Do not invent domains, IP addresses, tools, events, or findings.
3. Do not claim that an attack occurred unless the evidence proves it.
4. Explain each alert and identify its supporting evidence.
5. If the evidence is insufficient, clearly state that limitation.
6. Treat alerts as indicators for review, not proof of an attack.
7. Recommend reasonable investigative steps based on the evidence.
8. If a metric is zero, report it accurately.
9. Do not assume the identity of hosts or organizations.
10. Do not suggest specific attacks, such as DoS or DDoS,
    unless the supplied evidence supports that hypothesis.
11. Distinguish measured facts from possible explanations.
    If evidence is insufficient, say "Insufficient evidence to determine."
12. A high count alone does not prove an attack or malicious activity.
    State counts as measured facts, not threat conclusions.
13. Do not label traffic as high, abnormal, suspicious, or unusual
    unless a supplied threshold or baseline supports that description.

Use this format:

SUMMARY:
Summarize the supplied results.

EVIDENCE:
List only the relevant counts and detected alerts.
Do not repeat these instructions or rules.

SECURITY INTERPRETATION:
Explain what the evidence may indicate and what it does not prove.

NEXT STEPS:
Recommend reasonable investigative actions based on the evidence.
"""

    # Send the prompt to the local Llama model
    response = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    # Return the AI-generated explanation
    return response["message"]["content"]
