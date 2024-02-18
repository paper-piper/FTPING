from scapy.all import *
import time
from scapy.layers.inet import *

FILE_PATH = r"C:\Users\yonat\Downloads\hello.txt"
SERVER_IP = "127.0.0.1"

def send_file():
    with open(FILE_PATH, "r") as file:
        data = file.read()

    # Split data into chunks
    chunks = [data[i:i + 32] for i in range(0, len(data), 32)]

    for i, chunk in enumerate(chunks):
        packet = IP(dst=SERVER_IP) / ICMP() / Raw(load=chunk)
        send(packet)
        print(f"Sent chunk {i+1}/{len(chunks)}")

        # Wait for ACK
        while True:
            ack_packet = sniff(filter="icmp and host " + SERVER_IP, count=1)
            if Raw in ack_packet[0] and ack_packet[0][Raw].load.decode() == "ACK":
                print("ACK received")
                break
            else:
                print("Resending chunk")
                send(packet)


def main():
    send_file()


if __name__ == "__main__":
    main()
