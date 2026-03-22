import subprocess
import shlex

i = 62
while(i <= 70):
    for j in range(4, 21):
        cmd = shlex.split(f'/usr/bin/python3 /home/kali/Detection_Testing/pcapDistributionOrchestrator.py --folder /home/kali/Detection_Testing/NN/Data70/ --output /home/kali/Detection_Testing/NN/Regression/Distributions/dataset_n{i}_{j}.pcap --total_time 20 --arrival_distribution static --arrival_time 0 --duration_distribution constant --min_duration 20 --max_duration 20 --total_devices {i}')
        subprocess.run(cmd)
    i += 1