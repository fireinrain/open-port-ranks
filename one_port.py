import json
import os
import subprocess
from collections import defaultdict
from matplotlib import pyplot as plt
import requests


# Step 1: 获取 ASN 的 CIDR IP 段
def get_cidr_ips(asn):
    # 确保 asn 目录存在
    asn_dir = "asn"
    os.makedirs(asn_dir, exist_ok=True)

    file_path = os.path.join(asn_dir, f"{asn}")

    # 检查是否存在对应的 ASN 文件
    if os.path.exists(file_path):
        # 如果文件存在，读取文件内容
        with open(file_path, 'r') as file:
            cidrs = json.load(file)
        print(f"CIDR data for ASN {asn} loaded from file.")
    else:
        # 如果文件不存在，请求 API 数据
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


# Step 2: 使用 Nmap 扫描所有 IP 的端口
def scan_ip_range(cidr, output_file, scan_ports="443"):
    # masscan 默认输出为二进制格式，我们需要使用 -oL 来输出为列表格式
    cmd = ["masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=5", "-oL", output_file]
    print(f"Executing command: {' '.join(cmd)}")  # 打印执行的命令字符串

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Scan completed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        print(f"Exit status: {e.returncode}")
        print(f"Standard output: {e.stdout}")
        print(f"Standard error: {e.stderr}")


# 步骤 3: 解析 Nmap 输出并统计端口
def parse_masscan_output(file_path):
    port_counts = defaultdict(int)
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('open'):
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[2])
                    group = (port - 1) // 1000
                    port_counts[group] += 1
    return port_counts


# 步骤 4: 绘制条形图
def plot_port_statistics(port_counts, asn_number, scan_ports):
    result_dir = os.path.join('ports_results', asn_number)
    os.makedirs(result_dir, exist_ok=True)
    groups = list(range(66))
    counts = [port_counts[g] for g in groups]

    fig, ax = plt.subplots(figsize=(15, 8))
    bars = ax.bar(groups, counts)

    # 根据数量设置颜色
    max_count = max(counts)
    norm = plt.Normalize(0, max_count)
    for bar, count in zip(bars, counts):
        color = plt.cm.viridis(norm(count))
        bar.set_color(color)

    ax.set_xlabel('Port Range (in thousands)')
    ax.set_ylabel('Number of Open Ports')
    ax.set_title('Distribution of Open Ports (Mock Data)')
    ax.set_xticks(range(0, 66, 5))
    ax.set_xticklabels([f'{i}k-{i + 1}k' for i in range(0, 66, 5)])

    sm = plt.cm.ScalarMappable(cmap='viridis', norm=norm)
    sm.set_array([])  # 这行是必要的，尽管看起来没有意义
    cbar = plt.colorbar(sm, ax=ax, label='Relative Frequency')

    plt.tight_layout()
    save_path = os.path.join(result_dir, f'port_distribution_asn{asn_number}_{scan_ports}.png')
    plt.savefig(save_path)
    # plt.show()


# 主函数
def scan_and_genstatistics(asn_number, scan_ports):
    asn = asn_number
    # scan_ports = "0-65535"
    scan_ports = scan_ports
    cidrs = get_cidr_ips(asn)
    all_port_counts = defaultdict(int)

    # 创建一个目录来存储扫描结果
    output_dir = f"masscan_results/{asn}"
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, f"scan_result.txt")
    print(f"Scanning {cidrs[0]}...")
    cidrs_str = " ".join(cidrs)
    scan_ip_range(cidrs_str, output_file, scan_ports)
    try:
        port_counts = parse_masscan_output(output_file)
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
            print(file)
    return matching_files


def refresh_markdown(results_dir: str):
    start_directory = results_dir
    file_prefix = 'port_distribution'
    found_files = find_files(start_directory, file_prefix)
    print(f"发现统计图片: {found_files}")
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
    scan_and_genstatistics('906', '80')
    refresh_markdown('ports_results')


if __name__ == "__main__":
    main()
