import os
import argparse
import numpy as np
from scapy.all import rdpcap, wrpcap, PacketList
import csv

parser = argparse.ArgumentParser(description="Merge PCAPs with arrival and duration distributions.")
parser.add_argument('--folder', default="/home/kali/Detection_Testing/DataCH1", help='Path to folder with PCAP files.')
parser.add_argument('--output', required=True, help='Output merged PCAP file.')
parser.add_argument('--total_time', type=int, required=True, help='Total duration of final capture in minutes.')
parser.add_argument('--arrival_distribution', required=True, choices=['static', 'uniform', 'normal', 'poisson', 'bimodal', 'left_skewed'], help='Distribution for capture start times.')
parser.add_argument('--arrival_time', type=int, help='Arrival time for the static arrival distribution.')
parser.add_argument('--duration_distribution', required=True, choices=['constant', 'uniform', 'normal'], help='Distribution for capture active duration.')
parser.add_argument('--min_duration', type=int, default=1, help='Minimum active duration in minutes (default: 1).')
parser.add_argument('--max_duration', type=int, default=20, help='Maximum active duration in minutes (default: 20).')
parser.add_argument('--min_repetition_gap', type=float, default=5, help='Minimum gap between repeating captures in minutes (default: 5).')
parser.add_argument('--pcaps', default=None, help='Comma-separated list of PCAP filenames (default: all).')
parser.add_argument('--total_devices', default=None, type=int, help='Total number of devices seen on the final capture (some devices may be repeated) (default: all).')
args = parser.parse_args()

# Get list of PCAP files
if args.pcaps:
    pcaps_list = args.pcaps.split(',')
else:
    pcaps_list = [f for f in os.listdir(args.folder) if f.endswith('ch1.pcap')]
if not pcaps_list:
    raise ValueError("No PCAP files found in the folder or specified.")

if not args.total_devices:
    args.total_devices = len(pcaps_list)

total_seconds = args.total_time * 60.0
gap_sec = args.min_repetition_gap * 60
placements = []  # List of (pcap_file, start_time_sec, duration_sec, end_time_sec)

# Generate arrival times
if args.arrival_distribution == 'static':
    arrival_times = [args.arrival_time * 60.0] * args.total_devices
elif args.arrival_distribution == 'uniform':
    arrival_times = np.random.uniform(0, total_seconds, args.total_devices)
elif args.arrival_distribution == 'normal':
    mean = total_seconds / 2
    std_dev = total_seconds / 6
    arrival_times = np.random.normal(mean, std_dev, args.total_devices)
    arrival_times = np.clip(arrival_times, 0, total_seconds)
elif args.arrival_distribution == 'poisson':
    count = np.random.poisson(args.total_devices)
    arrival_times = np.random.uniform(0, total_seconds, count)
elif args.arrival_distribution == 'bimodal':
    mean1 = total_seconds * 0.3
    mean2 = total_seconds * 0.7
    std_dev = total_seconds / 6
    choice = np.random.choice([0, 1], args.total_devices, p=[0.5, 0.5])
    arrival_times = np.where(choice == 0,
                                np.random.normal(mean1, std_dev, args.total_devices),
                                np.random.normal(mean2, std_dev, args.total_devices))
    arrival_times = np.clip(arrival_times, 0, total_seconds)
elif args.arrival_distribution == 'left_skewed':
    alpha = 12.0
    beta  = 8.0
    arrival_times = total_seconds * np.random.beta(alpha, beta, args.total_devices)
arrival_times = np.sort(arrival_times)

min_sec = args.min_duration * 60.0
max_sec = args.max_duration * 60.0

# Assign duration to each arrival
if args.duration_distribution == 'constant':
    durations = [(min_sec + max_sec) / 2] * len(arrival_times)
elif args.duration_distribution == 'uniform':
    durations = np.random.uniform(min_sec, max_sec, len(arrival_times))
elif args.duration_distribution == 'normal':
    mean = (min_sec + max_sec) / 2
    std_dev = (max_sec - min_sec) / 6
    durations = np.clip(np.random.normal(mean, std_dev, len(arrival_times)), min_sec, max_sec)

# Assign PCAPs to placements
for start_sec, dur_sec in zip(arrival_times, durations):
    end_sec = min(start_sec + dur_sec, total_seconds)
    dur_sec = end_sec - start_sec

    captures_present = []
    for p in placements:
        if not (p[3] <= start_sec - gap_sec or end_sec + gap_sec <= p[1]):
            captures_present.append(p[0])

    available = [f for f in pcaps_list if f not in captures_present]
    if available:
        pcap_file = np.random.choice(available)
        placements.append((pcap_file, start_sec, dur_sec, end_sec))

# Load and place packets
all_packets = []
for pcap_file, start_sec, dur_sec, end_sec in placements:
    full_path = os.path.join(args.folder, pcap_file)
    try:
        packets = rdpcap(full_path)
    except Exception as e:
        print(f"Warning: Could not read {pcap_file}: {e}")
        continue

    if not packets:
        continue

    orig_start = packets[0].time

    i = 0
    while True:
        pkt = packets[i % len(packets)]
        new_time = start_sec + (pkt.time - orig_start) + (20 * 60 * (i // len(packets)))
        if (new_time >= total_seconds) or (new_time > end_sec):
            break
        all_packets.append(pkt.copy())
        all_packets[-1].time = new_time
        i += 1

if not all_packets:
    raise ValueError("No packets were placed. Check input PCAPs.")

# Sort timestamps
all_packets.sort(key=lambda p: p.time)

# Save merged PCAP
wrpcap(args.output, PacketList(all_packets))
print(f"Merged PCAP saved to: {args.output}")

# Sort according to start time for output files
placements.sort(key=lambda p: p[1])

# Human-readable placement summary
summary_path = args.output.replace('.pcap', '_placement_summary.txt')
with open(summary_path, 'w') as f:
    f.write("PCAP PLACEMENT SUMMARY\n")
    f.write("="*60 + "\n")
    f.write(f"Total duration: {args.total_time} minutes\n")
    f.write(f"Total devices (includes repetitions): {len(placements)}\n")
    f.write(f"Arrival distribution: {args.arrival_distribution} | Duration distribution: {args.duration_distribution}\n\n")
    f.write(f"{'File':<20} {'Start (min)':<12} {'End (min)':<10} {'Duration (min)':<15}\n")
    f.write("-" * 60 + "\n")
    for pcap_file, start_sec, dur_sec, end_sec in placements:
        f.write(f"{pcap_file:<20} {start_sec/60:>10.2f}  {end_sec/60:>10.2f}  {dur_sec/60:>12.2f}\n")
print(f"Placement summary saved to: {summary_path}")
os.system(f"cat {summary_path}")

# 5-minute interval CSV
interval_sec = 5 * 60
num_intervals = int(np.ceil(total_seconds / interval_sec))
interval_active = [[] for _ in range(num_intervals)]

for pcap_file, start_sec, dur_sec, end_sec in placements:
    start_idx = int(start_sec // interval_sec)
    end_idx = int(np.ceil(end_sec / interval_sec))
    for i in range(start_idx, min(end_idx, num_intervals)):
        interval_active[i].append(pcap_file)

csv_path = args.output.replace('.pcap', '_5min_intervals.csv')
with open(csv_path, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile, delimiter=';')
    n = max(len(interval) for interval in interval_active)

    for i in reversed(range(n)):
        row = []
        for interval in interval_active:
            if i + 1 > len(interval):
                row.append('')
            else:
                row.append(interval[i][:-5])
        writer.writerow(row)

print(f"5-minute interval CSV saved to: {csv_path}")
os.system(f"cat {csv_path}")