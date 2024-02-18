from scapy.all import *
import random
from scapy.layers.inet import *


def handle_packet(packet):
    if Raw in packet:
        data = packet[Raw].load.decode()
        print(f"Received: {data}")

        # Simulate packet loss
        if random.randint(1, 11) != 1:
            # Send ACK for received packet
            ack_packet = IP(dst=packet[IP].src) / ICMP(type="echo-reply") / Raw(load="ACK")
            send(ack_packet)
        else:
            print("Simulated packet loss")


def main():
    print("Starting FTPing server...")
    sniff(filter="icmp", prn=handle_packet)


if __name__ == "__main__":
    main()
