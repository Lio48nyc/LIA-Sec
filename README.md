# LIA-Sec

**LIA-Sec** (Live Intelligence & Analysis: Security Assistant) is a PCAP analysis tool with a local AI chatbot. It measures network traffic, flags indicators for review, and uses a local Ollama model to explain the results.

> Alerts are indicators for review, not proof of an attack. No alerts does not prove that no attack occurred.

## Features

- PCAP analysis with Scapy (DNS, ICMP, HTTP requests, TCP SYN/RST indicators)
- Rule-based detection with adjustable thresholds
- AI interpretation using a local Ollama model (no cloud service needed)
- Desktop chatbot (Tkinter) with follow-up questions about the latest report
- Export reports as `.txt` or `.json`

## Requirements

- Python 3.9 or newer
- [Ollama](https://ollama.com) installed and running
- Tkinter (included with Python on Windows and macOS; on Linux run `sudo apt install python3-tk`)

## Installation

```bash
git clone https://github.com/Lio48nyc/LIA-Sec.git
cd LIA-Sec
pip install -r requirements.txt
ollama pull llama3.2:3b
```

## Usage

Desktop chatbot:

```bash
python chatbot.py
```

Command line analysis:

```bash
python -m lia_sec.analyze_capture path/to/capture.pcapng
```

Chatbot commands: `/analyze`, `/summary`, `/alerts`, `/export`, `/help`

## Configuration

Set these environment variables to change the defaults:

| Variable | Default | Purpose |
|---|---|---|
| `LIA_MODEL` | `llama3.2:3b` | Ollama model to use |
| `LIA_NUM_CTX` | `8192` | Model context window size |
| `LIA_MAX_ALERTS` | `20` | Max alerts sent to the chatbot as context |
| `LIA_MAX_REPORT_CHARS` | `3000` | Max AI report characters sent as context |
| `LIA_HISTORY_LIMIT` | `12` | Recent chat messages kept for follow-ups |

Detection thresholds (DNS volume, SYN flood, port scan, TCP resets) are defined at the top of `lia_sec/packet_analysis.py`.

## Project structure

```
LIA-Sec/
├── chatbot.py
├── requirements.txt
└── lia_sec/
    ├── __init__.py
    ├── analyze_capture.py
    ├── ai_analysis.py
    └── packet_analysis.py
```

## Privacy note

PCAP files can contain real IP addresses, hostnames, and credentials. Do not commit capture files to this repository.

## Author

Created by LIO.
