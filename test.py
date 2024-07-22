import os
import random
from collections import defaultdict
from matplotlib import pyplot as plt


def generate_mock_data():
    port_counts = defaultdict(int)
    for _ in range(10000):  # 生成10000个随机端口
        port = random.randint(0, 65535)
        group = port // 1000
        port_counts[group] += 1
    return port_counts


def generate_mock_data2():
    port_counts = defaultdict(int)
    for _ in range(10000):  # 生成10000个随机端口
        port = random.choice(['80', '880', '993'])
        port_counts[port] += 1
    return port_counts


def plot_port_statistics(port_counts):
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
    plt.savefig('port_distribution_mock.png')
    plt.show()


def plot_port_statistics2(port_counts, asn_number, scan_ports):
    result_dir = os.path.join('ports_results', asn_number)
    os.makedirs(result_dir, exist_ok=True)

    if ',' in scan_ports:
        # 如果端口列表包含逗号，直接使用具体端口
        ports = sorted(port_counts.keys())
        counts = [port_counts[p] for p in ports]

        fig, ax = plt.subplots(figsize=(15, 8))
        bars = ax.bar(ports, counts)

        # 根据数量设置颜色
        max_count = max(counts)
        norm = plt.Normalize(0, max_count)
        for bar, count in zip(bars, counts):
            color = plt.cm.viridis(norm(count))
            bar.set_color(color)

        ax.set_xlabel('Port')
        ax.set_ylabel('Number of Open Ports')
        ax.set_title(f'Distribution of Open Ports (ASN {asn_number}, Ports: {scan_ports})')

        ax.set_xticks(ports)
        ax.set_xticklabels(ports, rotation=90)

    else:
        # 如果端口范围包含连字符，使用分组的形式
        port_ranges = scan_ports.split('-')
        start_port = int(port_ranges[0])
        end_port = int(port_ranges[1])
        num_groups = min(66, (end_port - start_port) // 1000 + 1)
        step = (end_port - start_port + 1) // num_groups
        groups = list(range(num_groups))
        counts = [0] * num_groups
        for port, count in port_counts.items():
            group = (port - start_port) // step
            if 0 <= group < num_groups:
                counts[group] += count

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
        ax.set_title(f'Distribution of Open Ports (ASN {asn_number}, Ports: {scan_ports})')

        ax.set_xticks(range(0, num_groups, max(num_groups // 10, 1)))
        ax.set_xticklabels([f'{i * step}k-{(i + 1) * step}k' for i in range(0, num_groups, max(num_groups // 10, 1))])

    sm = plt.cm.ScalarMappable(cmap='viridis', norm=norm)
    sm.set_array([])  # 这行是必要的，尽管看起来没有意义
    cbar = plt.colorbar(sm, ax=ax, label='Relative Frequency')

    plt.tight_layout()
    save_path = os.path.join(result_dir, f'port_distribution_asn{asn_number}_{scan_ports}.png')
    plt.savefig(save_path)
    # plt.show()


if __name__ == '__main__':
    # 生成模拟数据并调用函数
    # mock_port_counts = generate_mock_data()
    # plot_port_statistics(mock_port_counts)

    mock_port_counts2 = generate_mock_data2()
    plot_port_statistics2(mock_port_counts2,"906","80,880,993")
