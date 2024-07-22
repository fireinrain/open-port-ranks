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


if __name__ == '__main__':
    # 生成模拟数据并调用函数
    mock_port_counts = generate_mock_data()
    plot_port_statistics(mock_port_counts)
