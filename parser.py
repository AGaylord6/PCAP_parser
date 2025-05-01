'''

Andrew Gaylord

Parse pcap files and extract stats like RTT

'''

import sys
import argparse
from scapy.all import *

def parse_pcap(file_name, local_ip, remote_ip, port):
    '''
    parse_pcap

    Parse pcap file and extract data

    @params:
        file_name: pcap file name
        local_ip: source IP address
        remote_ip: destination IP address
        port: port number
    '''
    port = int(port)
    filtered_packets = []

    largestSize = 0
    localMSS = 0
    remoteMSS = 0
    localACKs = 0
    remoteACKs = 0
    allRTT = {}
    RTTs = []
    handshakeRTT = {}

    # read pcap as a stream instead of loading all at once
    with PcapReader(file_name) as packets:
        for pkt in packets:
            # break early if not IP or doesn't match IPs
            if not pkt.haslayer(IP):
                continue
            
            # cache packet details
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if not ((local_ip == src_ip and remote_ip == dst_ip) or 
                    (local_ip == dst_ip and remote_ip == src_ip)):
                continue

            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue

            src_port = pkt.sport
            dst_port = pkt.dport
            if port not in (src_port, dst_port):
                continue
            
            # we've passed all filters
            filtered_packets.append(pkt)

            if len(pkt) > largestSize:
                largestSize = len(pkt)

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                flags = tcp_layer.flags

                # MSS option check
                for option in tcp_layer.options:
                    if option[0] == 'MSS':
                        if src_ip == local_ip and localMSS == 0:
                            localMSS = option[1]
                        elif src_ip == remote_ip and remoteMSS == 0:
                            remoteMSS = option[1]

                # Pure ACK check
                if flags == 0x10 and len(tcp_layer.payload) == 0:
                    if src_ip == local_ip:
                        localACKs += 1
                    elif src_ip == remote_ip:
                        remoteACKs += 1

                # Handshake RTT
                seq_num = tcp_layer.seq
                ack_num = tcp_layer.ack

                is_syn = flags & 0x02
                is_ack = flags & 0x10

                if is_syn and not is_ack:
                    handshakeRTT[seq_num + 1] = [pkt.time, -1]
                elif is_syn and is_ack and (ack_num in handshakeRTT):
                    handshakeRTT[ack_num][1] = pkt.time

                # RTT tracking
                if src_ip == local_ip:
                    # create a new entry for the RTT (-1 to indicate not acked yet)
                    # seq number + data payload len => (start time, end time)
                    allRTT[seq_num + len(tcp_layer.payload)] = [pkt.time, -1]
                elif src_ip == remote_ip:
                    for key in list(allRTT.keys()):
                        # check all packets that haven't been acked yet (allowing for cumulative ACKs)
                        if allRTT[key][1] == -1 and ack_num >= key:
                            allRTT[key][1] = pkt.time
                            rtt = allRTT[key][1] - allRTT[key][0]
                            RTTs.append(rtt * 1000)  # ms
    
    print("File name: ", file_name)
    print("Local IP: ", local_ip)
    print("Remote IP: ", remote_ip)
    print("Port: ", port)
    print("")
    print(f"Total packets matching criteria: {len(filtered_packets)}")
    print(f"Largest packet size: {largestSize} bytes")
    print(f"Local MSS: {localMSS}")
    print(f"Remote MSS: {remoteMSS}")
    print("")
    print(f"Pure ACKs - Local: {localACKs}, Remote: {remoteACKs}")
    print("")

    handRTT = 0
    for start, end in handshakeRTT.values():
        if start != -1 and end != -1:
            # Calculate the RTT for the handshake
            handRTT = end - start
            break

    print(f"Handshake RTT: {handRTT} seconds ({handRTT * 1000} ms)\n")

    if len(RTTs) == 0:
        print("No RTT measurements found.")
        return

    # find all statistics
    meanRTT = sum(RTTs) / len(RTTs)
    minRTT = min(RTTs)
    maxRTT = max(RTTs)

    # Median calculation
    RTTs.sort()
    n = len(RTTs)
    if n % 2 == 0:
        medianRTT = (RTTs[n // 2 - 1] + RTTs[n // 2]) / 2
    else:
        medianRTT = RTTs[n // 2]

    print(f"RTT Statistics:")
    print(f"  Total RTT measurements found: {n}")
    print(f"  Mean RTT: {meanRTT} ms")
    print(f"  Median RTT: {medianRTT} ms")
    print(f"  Min RTT: {minRTT} ms")
    print(f"  Max RTT: {maxRTT} ms")
    print("")


if __name__ == "__main__":

    # set up auto argument parsing
    parser = argparse.ArgumentParser(description="Parse and filter a PCAP file by IPs and port.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("local_ip", help="Local IP address to match")
    parser.add_argument("remote_ip", help="Remote IP address to match")
    parser.add_argument("port", help="Port number to match")

    args = parser.parse_args()
    parse_pcap(args.pcap_file, args.local_ip, args.remote_ip, args.port)

