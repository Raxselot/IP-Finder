from scapy.all import ARP, Ether, srp

def scan_network(network_ip):
    arp = ARP(pdst=network_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

devices = scan_network("192.168.1.0/24")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
