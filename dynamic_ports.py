import json
import os
import subprocess
from collections import defaultdict
from matplotlib import pyplot as plt
import requests


def get_cidr_ips(asn):
    # Ensure ASN directory exists
    asn_dir = "asn"
    os.makedirs(asn_dir, exist_ok=True)

    file_path = os.path.join(asn_dir, f"{asn}")

    # Check if ASN file exists
    if os.path.exists(file_path):
        # Read file content if it exists
        with open(file_path, 'r') as file:
            cidrs = json.load(file)
        print(f"CIDR data for ASN {asn} loaded from file.")
    else:
        # Fetch data from API if file does not exist
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # Write data to file
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


def scan_ip_range(cidr, output_file, scan_ports="443"):
    cmd = ["masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=5", "-oL", output_file]
    print(f"Executing command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Scan completed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        print(f"Exit status: {e.returncode}")
        print(f"Standard output: {e.stdout}")
        print(f"Standard error: {e.stderr}")


def parse_masscan_output(file_path, scan_ports):
    port_counts = defaultdict(int)
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('open'):
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[2])
                    port_counts[port] += 1

    if ',' in scan_ports:
        groups = {port: count for port, count in port_counts.items()}
    else:
        start, end = map(int, scan_ports.split('-'))
        step = max((end - start + 1) // 66, 1)
        groups = defaultdict(int)
        for port in range(start, end + 1):
            group = (port - start) // step
            groups[group] += port_counts[port]

    return groups


def plot_port_statistics(port_counts, asn_number, scan_ports):
    result_dir = os.path.join('ports_results', asn_number)
    os.makedirs(result_dir, exist_ok=True)

    if ',' in scan_ports:
        groups = sorted(port_counts.keys())
        counts = [port_counts[g] for g in groups]
    else:
        step = max((int(scan_ports.split('-')[1]) - int(scan_ports.split('-')[0]) + 1) // 66, 1)
        groups = list(range(0, 66))
        counts = [port_counts[g] for g in groups]

    fig, ax = plt.subplots(figsize=(15, 8))
    bars = ax.bar(groups, counts)

    # Set colors based on counts
    max_count = max(counts)
    norm = plt.Normalize(0, max_count)
    for bar, count in zip(bars, counts):
        color = plt.cm.viridis(norm(count))
        bar.set_color(color)

    ax.set_xlabel('Port Range (in thousands)')
    ax.set_ylabel('Number of Open Ports')
    ax.set_title(f'Distribution of Open Ports for ASN {asn_number}')
    ax.set_xticks(range(0, len(groups), max(len(groups) // 10, 1)))
    ax.set_xticklabels([f'{i * step}k-{(i + 1) * step}k' for i in range(0, len(groups), max(len(groups) // 10, 1))])

    sm = plt.cm.ScalarMappable(cmap='viridis', norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=ax, label='Relative Frequency')

    plt.tight_layout()
    save_path = os.path.join(result_dir, f'port_distribution_asn{asn_number}_{scan_ports}.png')
    plt.savefig(save_path)
    # plt.show()


def scan_and_genstatistics(asn_number, scan_ports):
    asn = asn_number
    scan_ports = scan_ports
    cidrs = get_cidr_ips(asn)
    all_port_counts = defaultdict(int)

    output_dir = f"masscan_results/{asn}"
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, f"scan_result.txt")
    print(f"Scanning {cidrs[0]}...")
    cidrs_str = " ".join(cidrs)
    scan_ip_range(cidrs_str, output_file, scan_ports)
    try:
        port_counts = parse_masscan_output(output_file, scan_ports)
        for group, count in port_counts.items():
            all_port_counts[group] += count
    except FileNotFoundError:
        print(f"Scan result file not found for {cidrs[0]}. Skipping...")

    if all_port_counts:
        plot_port_statistics(all_port_counts, asn, scan_ports)
    else:
        print("No successful scans to plot.")


def find_files(start_dir, prefix):
    matching_files = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.startswith(prefix):
                abs_path = os.path.join(root, file)
                matching_files.append(abs_path)
    return matching_files


def refresh_markdown(results_dir: str):
    start_directory = results_dir
    file_prefix = 'port_distribution'
    found_files = find_files(start_directory, file_prefix)
    print(f"Found statistics images: {found_files}")
    markdown = '''
# open-ports-ranks
scan asn and detect the open port and make a statics with graph
## Open Ports Result    
'''
    markdown += '\n'

    images_nodes = [f'![{i.split("/")[-1]}]({i})' for i in found_files]
    images_nodes_str = "\n".join(images_nodes)

    markdown += images_nodes_str
    with open('README.md', 'w') as f:
        f.write(markdown)
        f.flush()


def main():
    # 80,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443
    # 80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880
    scan_and_genstatistics('906', '80,443,2052,2053,2082,2083,2086,2087,2095,2096,8080,8443,8880')
    refresh_markdown('ports_results')


if __name__ == "__main__":
    main()
