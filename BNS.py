from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Affiche le résumé du paquet
    print(f"Packet: {packet.summary()}")

    # Vérifie et affiche les informations IP
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")

        # Vérifie et affiche les informations TCP
        if TCP in packet:
            tcp_srcport = packet[TCP].sport
            tcp_dstport = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            print(f"TCP Source Port: {tcp_srcport}, TCP Destination Port: {tcp_dstport}")
            print(f"TCP Flags: {tcp_flags}")
        # Vérifie et affiche les informations UDP
        elif UDP in packet:
            udp_srcport = packet[UDP].sport
            udp_dstport = packet[UDP].dport
            print(f"UDP Source Port: {udp_srcport}, UDP Destination Port: {udp_dstport}")

        print("-" * 40)

def start_sniffer(iface=None, count=None):
    print("Starting packet capture...")
    # Capture les paquets
    sniff(iface=iface, prn=packet_callback, count=count, store=0)

if __name__ == "__main__":
    # Paramètres d'exécution
    iface = input("Enter the network interface (e.g., eth0, wlan0): ")
    try:
        count = int(input("Enter the number of packets to capture (0 for infinite): "))
    except ValueError:
        print("Invalid input for packet count. Capturing indefinitely.")
        count = 0

    start_sniffer(iface=iface, count=count)
