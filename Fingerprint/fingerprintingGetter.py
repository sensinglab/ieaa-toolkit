from scapy.all import *
import os
import argparse
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

def frame_processing(frame):

    ie = frame.getlayer(Dot11Elt)
    array_v = []

    while ie:
        if(ie.ID == 1):                 # Supported Rates
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 50):              # Extended Supported Rates
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 3):               # DS Parameter Set
            array_v.append(ie.ID)
            #array_v.append(ie.len)
        
        elif(ie.ID == 45):              # HT Capabilities
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 4):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        elif(ie.ID == 127):             # Extended Capabilities
            array_v.append(ie.ID)
            #array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 191):             # VHT Capabilities
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 70):              # RM Enabled Capabilities 
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 107):             # Interworking
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 59):              # Supported Operating Classes
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 221):             # Vendor Specific
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 5 and i != 7):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        ie = ie.payload
    
    footprint_mac = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()
    #print("Probe Request | Footprint: " + footprint_mac)
    return footprint_mac

def get_fingerprints(pcaps_list):
    devices_fingerprints = {}

    for pcap_file in pcaps_list:
        full_path = os.path.join("/home/kali/Detection_Testing/Data", pcap_file)
        packets = rdpcap(full_path)
        
        if not packets:
            print(f"No packets found in the {pcap_file} file.")
            continue

        print(f"Loaded {len(packets)} packets from {pcap_file}")

        devices_fingerprints[pcap_file] = set()

        for pkt in packets:
            devices_fingerprints[pcap_file].add(frame_processing(pkt))

    print(devices_fingerprints)



# Parse CLI arguments
parser = argparse.ArgumentParser(description="Get the fingerprints generated for the devices in the given PCAP files.")
parser.add_argument('--pcaps', default=None, required=True, help='Comma-separated list of PCAP filenames to use.')
args = parser.parse_args()

# Get list of PCAP files
if args.pcaps:
    pcaps_list = args.pcaps.split(',')

if not pcaps_list:
    raise ValueError("No PCAP files found in the folder or specified.")

get_fingerprints(pcaps_list)