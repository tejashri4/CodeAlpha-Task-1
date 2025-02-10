from scapy.all import sniff
def packet_callback(packet):
    
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src  
        ip_dst = packet["IP"].dst  
        protocol = packet["IP"].proto  

        print(f"Packet captured:")
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

       
        if packet.haslayer("TCP"):
            print("Protocol: TCP")
        elif packet.haslayer("UDP"):
            print("Protocol: UDP")
        elif packet.haslayer("ICMP"):
            print("Protocol: ICMP")

        print("=====================================")


def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0, filter="ip")  


start_sniffing()
