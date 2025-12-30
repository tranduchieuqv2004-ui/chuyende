#!/usr/bin/env python3
"""
STEP 4: VISUALIZE RESULTS
Tạo biểu đồ và báo cáo cho kết quả phân tích
"""

import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Backend cho môi trường không có display
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json
import sys
from pathlib import Path

# Cấu hình
plt.rcParams['figure.figsize'] = (18, 14)
sns.set_style('whitegrid')
plt.rcParams['font.size'] = 9

def create_feature_distribution_plots(df):
    """Biểu đồ phân bố các features"""
    
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle('FEATURE DISTRIBUTIONS', fontsize=16, fontweight='bold', y=0.995)
    
    # Domain length
    ax = axes[0, 0]
    ax.hist(df['subdomain_length'], bins=40, color='steelblue', edgecolor='black', alpha=0.7)
    mean_len = df['subdomain_length'].mean()
    threshold_len = mean_len + 2 * df['subdomain_length'].std()
    ax.axvline(threshold_len, color='red', linestyle='--', linewidth=2, label=f'Threshold: {threshold_len:.1f}')
    ax.set_xlabel('Subdomain Length (chars)')
    ax.set_ylabel('Frequency')
    ax.set_title('Subdomain Length Distribution')
    ax.legend()
    
    # Entropy
    ax = axes[0, 1]
    ax.hist(df['domain_entropy'], bins=40, color='orange', edgecolor='black', alpha=0.7)
    mean_ent = df['domain_entropy'].mean()
    threshold_ent = mean_ent + 1.5 * df['domain_entropy'].std()
    ax.axvline(threshold_ent, color='red', linestyle='--', linewidth=2, label=f'Threshold: {threshold_ent:.2f}')
    ax.set_xlabel('Domain Entropy')
    ax.set_ylabel('Frequency')
    ax.set_title('Domain Entropy Distribution (DGA Detection)')
    ax.legend()
    
    # Query rate
    ax = axes[0, 2]
    query_rates = df.groupby('client_ip')['query_rate'].first()
    ax.hist(query_rates, bins=30, color='green', edgecolor='black', alpha=0.7)
    mean_qr = query_rates.mean()
    threshold_qr = mean_qr + 2 * query_rates.std()
    ax.axvline(threshold_qr, color='red', linestyle='--', linewidth=2, label=f'Threshold: {threshold_qr:.2f}')
    ax.set_xlabel('Query Rate (queries/sec)')
    ax.set_ylabel('Frequency')
    ax.set_title('Query Rate Distribution (Burst Detection)')
    ax.legend()
    
    # Consonant ratio
    ax = axes[1, 0]
    ax.hist(df['consonant_ratio'], bins=40, color='purple', edgecolor='black', alpha=0.7)
    ax.axvline(0.65, color='red', linestyle='--', linewidth=2, label='DGA Threshold: 0.65')
    ax.set_xlabel('Consonant Ratio')
    ax.set_ylabel('Frequency')
    ax.set_title('Consonant Ratio (DGA Pattern)')
    ax.legend()
    
    # Queries per second
    ax = axes[1, 1]
    ax.hist(df['queries_per_sec'], bins=50, color='coral', edgecolor='black', alpha=0.7)
    ax.axvline(10, color='red', linestyle='--', linewidth=2, label='Burst Threshold: 10')
    ax.set_xlabel('Queries per Second')
    ax.set_ylabel('Frequency')
    ax.set_title('Burst Pattern Detection')
    ax.legend()
    ax.set_xlim(0, 30)
    
    # Domain diversity
    ax = axes[1, 2]
    diversity = df.groupby('client_ip')['domain_diversity'].first()
    ax.hist(diversity, bins=30, color='teal', edgecolor='black', alpha=0.7)
    ax.axvline(0.3, color='red', linestyle='--', linewidth=2, label='Low Diversity: <0.3')
    ax.set_xlabel('Domain Diversity')
    ax.set_ylabel('Frequency')
    ax.set_title('Domain Diversity (Scanning Detection)')
    ax.legend()
    
    plt.tight_layout()
    plt.savefig('results/1_feature_distributions.png', dpi=300, bbox_inches='tight')
    print("   ✓ Saved: results/1_feature_distributions.png")
    plt.close()

def create_anomaly_detection_plots(df):
    """Biểu đồ phát hiện anomalies"""
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('ANOMALY DETECTION RESULTS', fontsize=16, fontweight='bold')
    
    # Scatter: Length vs Entropy
    ax = axes[0, 0]
    
    normal = df[(df['subdomain_length'] <= 30) & (df['domain_entropy'] <= 3.8)]
    ax.scatter(normal['subdomain_length'], normal['domain_entropy'], 
              alpha=0.5, s=20, c='blue', label='Normal')
    
    tunneling = df[df['subdomain_length'] > 30]
    if len(tunneling) > 0:
        ax.scatter(tunneling['subdomain_length'], tunneling['domain_entropy'],
                  alpha=0.8, s=50, c='red', marker='^', label='Tunneling', edgecolors='black')
    
    dga = df[(df['domain_entropy'] > 3.8) & (df['subdomain_length'] <= 30)]
    if len(dga) > 0:
        ax.scatter(dga['subdomain_length'], dga['domain_entropy'],
                  alpha=0.8, s=50, c='orange', marker='s', label='DGA', edgecolors='black')
    
    ax.axhline(3.8, color='orange', linestyle='--', alpha=0.5, label='DGA threshold')
    ax.axvline(30, color='red', linestyle='--', alpha=0.5, label='Tunneling threshold')
    ax.set_xlabel('Subdomain Length')
    ax.set_ylabel('Domain Entropy')
    ax.set_title('DNS Tunneling & DGA Detection')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Timeline
    ax = axes[0, 1]
    df_copy = df.copy()
    df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
    timeline = df_copy.set_index('timestamp').resample('1min').size()
    ax.plot(timeline.index, timeline.values, linewidth=2, color='steelblue', label='Traffic')
    
    mean_traffic = timeline.mean()
    threshold = mean_traffic + 2 * timeline.std()
    ax.axhline(threshold, color='red', linestyle='--', linewidth=2, label=f'Threshold: {threshold:.0f}')
    
    spikes = timeline[timeline > threshold]
    if len(spikes) > 0:
        ax.scatter(spikes.index, spikes.values, color='red', s=100, zorder=5, label='Spikes')
    
    ax.set_xlabel('Time')
    ax.set_ylabel('Queries per Minute')
    ax.set_title('Traffic Timeline with Burst Detection')
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
    
    # IP behavior
    ax = axes[1, 0]
    ip_stats = df.groupby('client_ip').agg({
        'query_rate': 'first',
        'domain_diversity': 'first'
    })
    
    normal_ips = ip_stats[(ip_stats['query_rate'] <= 5) & (ip_stats['domain_diversity'] >= 0.3)]
    burst_ips = ip_stats[ip_stats['query_rate'] > 5]
    scan_ips = ip_stats[ip_stats['domain_diversity'] < 0.3]
    
    if len(normal_ips) > 0:
        ax.scatter(normal_ips['query_rate'], normal_ips['domain_diversity'],
                  alpha=0.6, s=60, c='green', label='Normal', edgecolors='black')
    if len(burst_ips) > 0:
        ax.scatter(burst_ips['query_rate'], burst_ips['domain_diversity'],
                  alpha=0.8, s=80, c='red', marker='^', label='Burst Attack', edgecolors='black')
    if len(scan_ips) > 0:
        ax.scatter(scan_ips['query_rate'], scan_ips['domain_diversity'],
                  alpha=0.8, s=80, c='orange', marker='s', label='Scanning', edgecolors='black')
    
    ax.axhline(0.3, color='orange', linestyle='--', alpha=0.5)
    ax.axvline(5, color='red', linestyle='--', alpha=0.5)
    ax.set_xlabel('Query Rate (q/s)')
    ax.set_ylabel('Domain Diversity')
    ax.set_title('IP Behavior Classification')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Attack summary
    ax = axes[1, 1]
    
    # FIXED: Consistent với step3 (3-5s thay vì 2.5-5.5s)
    detections = {
        'DNS Burst': len(df[df['queries_per_sec'] > 10]),
        'Suspicious\nDomains': len(df[df['has_suspicious_tld'] | df['has_suspicious_keyword']]),
        'DNS\nTunneling': len(df[(df['subdomain_length'] > 30) & (df['domain_entropy'] > 3.5)]),
        'DGA\nDomains': len(df[(df['domain_entropy'] > 3.8) & (df['consonant_ratio'] > 0.65)]),
        'Port\nScanning': len(df[df['queries_per_10sec'] > 20]),
        'Botnet\nBeacons': len(df[(df['time_diff'] >= 3.0) & (df['time_diff'] <= 5.0)])
    }
    
    colors = ['#ff6b6b', '#ee5a6f', '#c44569', '#f8b500', '#f39c12', '#e67e22']
    bars = ax.bar(range(len(detections)), detections.values(), color=colors, edgecolor='black', linewidth=1.5)
    ax.set_xticks(range(len(detections)))
    ax.set_xticklabels(detections.keys(), rotation=0, fontsize=9)
    ax.set_ylabel('Number of Detections')
    ax.set_title('Attack Detection Summary')
    ax.grid(True, alpha=0.3, axis='y')
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}',
               ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig('results/2_anomaly_detection.png', dpi=300, bbox_inches='tight')
    print("   ✓ Saved: results/2_anomaly_detection.png")
    plt.close()

def create_technique_comparison(df):
    """So sánh 3 techniques"""
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle('DETECTION TECHNIQUE COMPARISON', fontsize=16, fontweight='bold')
    
    with open('results/detection_summary.json', 'r') as f:
        summary = json.load(f)
    
    techniques = ['statistical', 'rule_based', 'behavioral']
    titles = ['Statistical Methods', 'Rule-based Methods', 'Behavioral Analysis']
    colors_list = [plt.cm.Blues, plt.cm.Reds, plt.cm.Greens]
    
    for idx, (tech, title, cmap) in enumerate(zip(techniques, titles, colors_list)):
        ax = axes[idx]
        
        data = summary[tech]
        names = list(data.keys())
        values = list(data.values())
        
        colors = cmap(np.linspace(0.4, 0.8, len(names)))
        bars = ax.bar(range(len(names)), values, color=colors, edgecolor='black', linewidth=1.5)
        
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels([n.replace('_', '\n') for n in names], rotation=0, fontsize=8)
        ax.set_ylabel('Detections')
        ax.set_title(title, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontweight='bold', fontsize=9)
    
    plt.tight_layout()
    plt.savefig('results/3_technique_comparison.png', dpi=300, bbox_inches='tight')
    print("   ✓ Saved: results/3_technique_comparison.png")
    plt.close()

def create_detailed_report():
    """Tạo báo cáo chi tiết"""
    
    df = pd.read_csv('logs/features.csv')
    with open('results/detection_summary.json', 'r') as f:
        summary = json.load(f)
    
    report = []
    report.append("="*80)
    report.append("DETAILED ANALYSIS REPORT")
    report.append("WiFi Security Anomaly Detection Lab")
    report.append("="*80)
    report.append(f"\nGenerated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Data period: {df['timestamp'].min()} to {df['timestamp'].max()}")
    
    report.append("\n" + "-"*80)
    report.append("1. DATA OVERVIEW")
    report.append("-"*80)
    report.append(f"Total DNS queries: {len(df):,}")
    report.append(f"Unique IPs: {df['client_ip'].nunique()}")
    report.append(f"Unique domains: {df['domain'].nunique()}")
    
    time_span = (pd.to_datetime(df['timestamp'].max()) - pd.to_datetime(df['timestamp'].min())).total_seconds() / 60
    report.append(f"Time span: {time_span:.1f} minutes")
    
    report.append("\n" + "-"*80)
    report.append("2. FEATURE STATISTICS")
    report.append("-"*80)
    report.append(f"Average domain length: {df['subdomain_length'].mean():.1f} chars")
    report.append(f"Average entropy: {df['domain_entropy'].mean():.2f}")
    report.append(f"Average query rate: {df['query_rate'].mean():.2f} q/s")
    report.append(f"Suspicious TLD rate: {df['has_suspicious_tld'].mean()*100:.1f}%")
    report.append(f"Suspicious keyword rate: {df['has_suspicious_keyword'].mean()*100:.1f}%")
    
    report.append("\n" + "-"*80)
    report.append("3. DETECTION RESULTS")
    report.append("-"*80)
    
    report.append("\n   A. Statistical Methods:")
    for name, count in summary['statistical'].items():
        report.append(f"      - {name.replace('_', ' ').title()}: {count:,} anomalies")
    
    report.append("\n   B. Rule-based Methods:")
    for name, count in summary['rule_based'].items():
        report.append(f"      - {name.replace('_', ' ').title()}: {count:,} detections")
    
    report.append("\n   C. Behavioral Analysis:")
    for name, count in summary['behavioral'].items():
        report.append(f"      - {name.replace('_', ' ').title()}: {count:,} patterns")
    
    report.append("\n" + "-"*80)
    report.append("4. TOP ANOMALOUS IPs")
    report.append("-"*80)
    
    ip_scores = df.groupby('client_ip').agg({
        'query_rate': 'first',
        'domain_diversity': 'first',
        'queries_per_sec': 'max'
    })
    
    # Scoring: query_rate>5 (3pts) + low_diversity<0.3 (2pts) + burst>10 (3pts)
    ip_scores['anomaly_score'] = (
        (ip_scores['query_rate'] > 5).astype(int) * 3 +
        (ip_scores['domain_diversity'] < 0.3).astype(int) * 2 +
        (ip_scores['queries_per_sec'] > 10).astype(int) * 3
    )
    
    top_ips = ip_scores.nlargest(5, 'anomaly_score')
    
    for ip, row in top_ips.iterrows():
        report.append(f"\n   IP: {ip}")
        report.append(f"   - Query rate: {row['query_rate']:.2f} q/s")
        report.append(f"   - Domain diversity: {row['domain_diversity']:.2f}")
        report.append(f"   - Max burst: {row['queries_per_sec']:.0f} q/s")
        report.append(f"   - Anomaly score: {row['anomaly_score']:.0f}/8")
    
    report.append("\n" + "-"*80)
    report.append("5. RECOMMENDATIONS")
    report.append("-"*80)
    
    total_anomalies = sum(sum(v.values()) for v in summary.values())
    
    if total_anomalies > 100:
        report.append("    HIGH RISK - Nhiều anomalies phát hiện!")
    elif total_anomalies > 20:
        report.append("     MEDIUM RISK - Một số anomalies cần kiểm tra")
    else:
        report.append("    LOW RISK - Ít anomalies")
    
    report.append("\n   Actions:")
    report.append("   1. Điều tra các IP có anomaly score cao")
    report.append("   2. Block các domain với TLD đáng ngờ")
    report.append("   3. Implement rate limiting cho DNS queries")
    report.append("   4. Monitor traffic patterns đều đặn")
    report.append("   5. Deploy IDS/IPS solution")
    
    report.append("\n" + "="*80)
    
    report_text = '\n'.join(report)
    with open('results/detailed_report.txt', 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print("   ✓ Saved: results/detailed_report.txt")
    return report_text

def main():
    print("="*70)
    print("STEP 4: VISUALIZE RESULTS")
    print("="*70)
    print()
    
    # Check files exist
    features_file = Path('logs/features.csv')
    summary_file = Path('results/detection_summary.json')
    
    if not features_file.exists():
        print(" Error: logs/features.csv not found!")
        print("   Please run step2_extract_features.py first.")
        return 1
    
    if not summary_file.exists():
        print(" Error: results/detection_summary.json not found!")
        print("   Please run step3_detect_anomalies.py first.")
        return 1
    
    # Load data
    try:
        df = pd.read_csv(features_file)
        print(f" Loaded {len(df):,} records\n")
    except Exception as e:
        print(f" Error loading features: {e}")
        return 1
    
    if len(df) == 0:
        print(" Error: Features file is empty!")
        return 1
    
    # Create results directory
    results_dir = Path('results')
    results_dir.mkdir(exist_ok=True)
    
    # Create visualizations
    print("   Creating visualizations...")
    try:
        create_feature_distribution_plots(df)
        create_anomaly_detection_plots(df)
        create_technique_comparison(df)
    except Exception as e:
        print(f"\n  Warning: Some visualizations failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Create report
    print("\n   Creating detailed report...")
    try:
        report = create_detailed_report()
    except Exception as e:
        print(f"  Warning: Report creation failed: {e}")
    
    print("\n" + "="*70)
    print(" VISUALIZATION COMPLETED")
    print("="*70)
    print("\n Output files:")
    print("   - results/1_feature_distributions.png")
    print("   - results/2_anomaly_detection.png")
    print("   - results/3_technique_comparison.png")
    print("   - results/detailed_report.txt")
    print("\n Mở các file PNG để xem biểu đồ phân tích!")
    print(f"\n View report: cat results/detailed_report.txt")
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)