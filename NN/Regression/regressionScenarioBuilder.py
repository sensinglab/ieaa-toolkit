import os
import numpy as np
import csv
import random
from scapy.all import rdpcap, PcapWriter, Dot11

# =====================================================================
# STATIC CONFIGURATION
# =====================================================================
TEMPLATE_FOLDER = "/home/kali/Detection_Testing/NN/Data70/"
OUTPUT_DIR = "/home/kali/Detection_Testing/NN/Regression/Distributions/"

TOTAL_TIME_MIN = 20
ARRIVAL_DISTRIBUTION = 'static'
ARRIVAL_TIME_MIN = 0
DURATION_DISTRIBUTION = 'constant'
MIN_DURATION_MIN = 20
MAX_DURATION_MIN = 20

START_DEVICES = 85
END_DEVICES = 300
ITERATIONS_PER_STEP = 20
# =====================================================================

pcap_cache = {}

def load_templates_to_memory():
    pcaps_list = [f for f in os.listdir(TEMPLATE_FOLDER) if f.endswith('ch1.pcap')]
    if not pcaps_list:
        pcaps_list = [f for f in os.listdir(TEMPLATE_FOLDER) if f.endswith('.pcap')]

    if not pcaps_list:
        raise ValueError(f"No PCAP files found in {TEMPLATE_FOLDER}")

    for filename in pcaps_list:
        path = os.path.join(TEMPLATE_FOLDER, filename)
        try:
            packets = rdpcap(path)
            if packets:
                pcap_cache[filename] = packets
        except Exception as e:
            pass

    if not pcap_cache:
        raise ValueError("No template PCAPs could be successfully loaded.")

def randomize_mac():
    """Generates a locally administered, randomized MAC address."""
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
    )

def generate_schedule(total_devices):
    if ARRIVAL_DISTRIBUTION == 'static':
        arrival_times = [ARRIVAL_TIME_MIN * 60.0] * total_devices
    
    arrival_times = np.sort(arrival_times)

    min_sec = MIN_DURATION_MIN * 60.0
    max_sec = MAX_DURATION_MIN * 60.0

    if DURATION_DISTRIBUTION == 'constant':
        durations = [(min_sec + max_sec) / 2] * len(arrival_times)
    
    return arrival_times, durations


def write_summaries(output_path, placements, total_seconds, devices):
    interval_sec = 5 * 60
    num_intervals = int(np.ceil(total_seconds / interval_sec))
    interval_active = [[] for _ in range(num_intervals)]

    for pcap_file, start_sec, _, end_sec in placements:
        start_idx = int(start_sec // interval_sec)
        end_idx = int(np.ceil(end_sec / interval_sec))
        for i in range(start_idx, min(end_idx, num_intervals)):
            interval_active[i].append(pcap_file)

    csv_path = output_path.replace('.pcap', '_5min_intervals.csv')
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=';')
        n = max((len(interval) for interval in interval_active), default=0)

        for i in reversed(range(n)):
            row = []
            for interval in interval_active:
                if i + 1 > len(interval):
                    row.append('')
                else:
                    row.append(interval[i][:-5])
            writer.writerow(row)


def build_scenario(params):
    devices, iteration = params
    filename = f"dataset_n{devices}_{iteration}.pcap"
    output_path = os.path.join(OUTPUT_DIR, filename)

    print(f"Building {filename}...", flush=True)

    total_seconds = TOTAL_TIME_MIN * 60.0
    arrival_times, durations = generate_schedule(devices)
    pcaps_list = list(pcap_cache.keys())

    placements = []
    for start_sec, dur_sec in zip(arrival_times, durations):
        end_sec = min(start_sec + dur_sec, total_seconds)
        actual_dur_sec = end_sec - start_sec
        pcap_file = np.random.choice(pcaps_list)
        placements.append((pcap_file, start_sec, actual_dur_sec, end_sec))

    all_packets = []
    for pcap_file, start_sec, dur_sec, end_sec in placements:
        packets = pcap_cache[pcap_file]
        orig_start = packets[0].time
        num_pkts = len(packets)
        
        placement_mac = randomize_mac()

        i = 0
        while True:
            pkt = packets[i % num_pkts]
            new_time = start_sec + (pkt.time - orig_start) + (1200 * (i // num_pkts))
            if (new_time >= total_seconds) or (new_time > end_sec):
                break
            
            pkt_copy = pkt.copy()
            pkt_copy.time = new_time
            
            if pkt_copy.haslayer(Dot11):
                pkt_copy[Dot11].addr2 = placement_mac
                
            all_packets.append(pkt_copy)
            i += 1

    if not all_packets:
        return

    all_packets.sort(key=lambda p: p.time)

    with PcapWriter(output_path, sync=False) as writer:
        writer.write(all_packets)

    write_summaries(output_path, placements, total_seconds, devices)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    load_templates_to_memory()

    print("Starting batch simulation sequentially...", flush=True)

    for devices in range(START_DEVICES, END_DEVICES + 1):
        for iteration in range(1, ITERATIONS_PER_STEP + 1):
            build_scenario((devices, iteration))

    print("Batch simulation complete.", flush=True)


if __name__ == "__main__":
    main()