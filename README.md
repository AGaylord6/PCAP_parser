# PCAP Parser

For Computer Networks class

To set up parser virtual environment run (installs scapy): 

./setup_venv.sh

To run parser (uses virtual env + prints to file automatically): 

./run_parser.sh

Optionally use args: 

./run_parser.sh [pcap_file] [local_ip] [remote_ip] [port] [output_file]

Defaults

  pcap_file     = Cap-Part3-Small.pcap

  local_ip      = 129.74.152.86

  remote_ip     = 10.33.154.65

  port          = 80

  output_file   = parser_output.txt

