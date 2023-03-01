from scapy.all import *
import subprocess

# Search for the network key on the device
def find_network_key():
    result = subprocess.run(['netsh', 'wlan', 'show', 'profile'], capture_output=True, text=True)
    profiles = [line.split(':')[1].strip() for line in result.stdout.split('\n') if 'All User Profile' in line]

    network_key = None
    for profile in profiles:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Key Content' in line:
                network_key = line.split(':')[1].strip()
                print(f'Found network key for profile {profile}: {network_key}')
                break
        if network_key:
            break

    return network_key

# Decode the packet payload
def decode_packet(packet, network_key):
   if packet.haslayer(TCP):
       ip = packet[IP].src
       port = packet[TCP].sport
       payload = packet[TCP].payload
       try:
           decoded_payload = payload.decrypt(key=network_key).decode('utf-8', errors='ignore')
           print(f'Found TCP packet from {ip}:{port} with decrypted payload: {decoded_payload}')
       except:
           print(f'Found TCP packet from {ip}:{port} with undecryptable payload')
   elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
       ip = packet[IP].src
       try:
           decoded_payload = packet[Raw].load.decode('utf-8', errors='ignore')
           print(f'Found ICMP ping request from {ip} with decrypted payload: {decoded_payload}')
       except:
           print(f'Found ICMP ping request from {ip} with undecryptable payload')

# Capture network traffic and decode payloads
def capture_traffic(network_key):
    sniff(filter="tcp or icmp", prn=lambda packet: decode_packet(packet, network_key))

if __name__ == '__main__':
    network_key = find_network_key()
    if not network_key:
        print('Unable to find network key')
    else:
        capture_traffic(network_key)
