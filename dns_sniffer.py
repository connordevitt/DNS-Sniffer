from scapy.all import sniff, DNS, DNSQR

def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        print(f"DNS Query: {packet[DNSQR].qname.decode()}")

sniff(filter="udp port 53", prn=process_packet, store=False)
