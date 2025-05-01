#!/bin/bash

show_help() {
  echo "Usage: ./run_parser.sh [pcap_file] [local_ip] [remote_ip] [port] [output_file]"
  echo ""
  echo "Defaults:"
  echo "  pcap_file     = Cap-Part3-Small.pcap"
  echo "  local_ip      = 129.74.152.86"
  echo "  remote_ip     = 10.33.154.65"
  echo "  port          = 80"
  echo "  output_file   = parser_output.txt"
  echo ""
  echo "You can override any of the defaults by passing arguments in order."
  echo "Example:"
  echo "  ./run_parser.sh mycap.pcap 129.74.152.86 10.33.154.65 80 results.txt"
  exit 0
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  show_help
fi

# Default values
PCAP_FILE="Cap-Part3-Small.pcap"
LOCAL_IP="129.74.152.86"
REMOTE_IP="10.33.154.65"
PORT="80"
OUTPUT_FILE="parser_output.txt"

# Override with command-line arguments if provided
if [ "$1" != "" ]; then PCAP_FILE="$1"; fi
if [ "$2" != "" ]; then LOCAL_IP="$2"; fi
if [ "$3" != "" ]; then REMOTE_IP="$3"; fi
if [ "$4" != "" ]; then PORT="$4"; fi
if [ "$5" != "" ]; then OUTPUT_FILE="$5"; fi

# check if we have /bin/ or /Scripts/ in our .venv folder
if [ -d ".venv/bin" ]; then
  PYTHON="./.venv/bin/python3"
elif [ -d ".venv/Scripts" ]; then
  PYTHON="./.venv/Scripts/python"
else
  echo "Python not found in .venv"
  exit 1
fi

SCRIPT="parser.py"

$PYTHON $SCRIPT "$PCAP_FILE" "$LOCAL_IP" "$REMOTE_IP" "$PORT" > "$OUTPUT_FILE" 2>&1
