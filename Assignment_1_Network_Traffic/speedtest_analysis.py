import dpkt
import socket
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse

def parse_pcapng(file_path):
    mp = {}
    total_packets = 0
    total_port443_packets = 0
    total_packets_size = 0
    total_port443_packets_size = 0
    download_data = []
    upload_data = []
    time_start = 0

    def is_port_443(ip):
        return isinstance(ip.data, dpkt.tcp.TCP) and (ip.data.dport == 443 or ip.data.sport == 443)

    with open(file_path, 'rb') as f:
        pcapng = dpkt.pcapng.Reader(f)
        
        for timestamp, buf in pcapng:
            if total_packets == 0:
                time_start = timestamp
            packet_len = len(buf)
            total_packets += 1
            total_packets_size += packet_len
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                if isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6):
                    ip = eth.data
                    src_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.dst)
                    
                    if is_port_443(ip):
                        total_port443_packets += 1
                        total_port443_packets_size += packet_len
                        mp[src_ip] = mp.get(src_ip, 0) + packet_len
                        mp[dst_ip] = mp.get(dst_ip, 0) + packet_len
                        
                        if ip.data.dport == 443:  # Upload
                            upload_data.append([timestamp-time_start, packet_len])
                        elif ip.data.sport == 443:  # Download
                            download_data.append([timestamp-time_start, packet_len])
                        
                else:
                    # For non-IP packets
                    src_ip = dst_ip = "non-IP"
                    mp[src_ip] = mp.get(src_ip, 0) + 1
                
            except Exception as e:
                # print(f"Error processing packet: {e}")
                continue

    # print(f"Total Packets: {total_packets}")
    # print(f"Total Packets transferred on port 443: {total_port443_packets}")
    # print(f"Percentage of speedtest traffic in terms of packet transfer: {(total_port443_packets/total_packets)*100:.2f}%" )
    # print('\n')
    # print(f"Total Packets Size: {total_packets_size}")
    # print(f"Total Packets size transferred from port 443: {total_port443_packets_size}")
    # print(f"Percentage of speedtest traffic in terms of bytes transfer: {(total_port443_packets_size/total_packets_size)*100:.2f}%" )
    
    # print(download_data)
    return download_data, upload_data

def calculate_average_speed(data, threshold_mbps):
    # Calculate throughput per second
    throughput_by_second = defaultdict(int)

    for timestamp, packet_len in data:
        second = int(timestamp)  # Use integer second value
        throughput_by_second[second] += packet_len

    # Filter seconds where throughput is below the threshold
    filtered_throughput = {second: throughput for second, throughput in throughput_by_second.items() if (throughput * 8) / 1_000_000 > threshold_mbps}
    
    if not filtered_throughput:
        return 0
    
    total_time = max(filtered_throughput.keys()) - min(filtered_throughput.keys()) if len(filtered_throughput) > 1 else 1  # To avoid division by zero
    total_bytes = sum(filtered_throughput.values())
    average_speed_mbps = (total_bytes * 8) / (total_time * 1_000_000)  # Convert to Mbps
    
    return average_speed_mbps

def calc_peaks(data):
    throughput_by_second = defaultdict(int)
    for timestamp, packet_len in data:
        second = int(timestamp)
        throughput_by_second[second] += packet_len
    peak_num = 0
    peak_num = max(throughput_by_second.values(), default=0)
    return peak_num

def calculate_average_throughput_per_second(data, state):
    throughput_by_second = defaultdict(int)

    for timestamp, packet_len in data:
        second = int(timestamp)  
        throughput_by_second[second] += packet_len

    sorted_seconds = sorted(throughput_by_second.keys())
    average_throughput = [throughput_by_second[second] for second in sorted_seconds]
    
    return sorted_seconds, average_throughput

def plot_throughput(download_data, upload_data):
    download_seconds, download_throughput = calculate_average_throughput_per_second(download_data, 1)
    upload_seconds, upload_throughput = calculate_average_throughput_per_second(upload_data , 0)

    plt.figure(figsize=(12, 6))
    
    plt.plot(download_seconds, download_throughput, label='Download Throughput', color='blue')
    plt.plot(upload_seconds, upload_throughput, label='Upload Throughput', color='green')
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Throughput (bytes per second)')
    plt.title('Observed Throughput Over Time')
    plt.legend()
    plt.grid(True)
    
    # Save the plot as a PNG file
    plt.savefig('throughput_plot.png')
    # print("Plot saved as 'throughput_plot.png'")

def main():
    parser = argparse.ArgumentParser(description='Analyze speed test data from a pcapng file.')
    parser.add_argument('file', help='Path to the pcapng file')
    parser.add_argument('--plot', action='store_true', help='Generate a time-series plot of throughput')
    parser.add_argument('--throughput', action='store_true', help='Output average download and upload speeds')

    args = parser.parse_args()
    pcapng_file = args.file
    download_data, upload_data = parse_pcapng(pcapng_file)
    download_peak = 0
    upload_peak = 0

    if args.plot:
        plot_throughput(download_data, upload_data)

    if args.throughput:
        download_peak = calc_peaks(download_data)
        upload_peak = calc_peaks(upload_data)
        download_peak = (download_peak * 8)/(1_000_000)
        upload_peak = (upload_peak * 8)/(1_000_000)
        threshold_ratio = 0.15

        down_speed = 0
        up_speed = 0
        if download_data:
            down_speed = calculate_average_speed(download_data, threshold_ratio*download_peak)
            # print(f"Average Download Speed: {down_speed:.2f} Mbps")
        
        if upload_data:
            up_speed = calculate_average_speed(upload_data, threshold_ratio*upload_peak)
            # print(f"Average Upload Speed: {up_speed:.2f} Mbps")
        print(f"{down_speed:.2f},{up_speed:.2f}")

if __name__ == "__main__":
    main()
    
    