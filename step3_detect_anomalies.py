#!/usr/bin/env python3
"""
STEP 3: APPLY DETECTION TECHNIQUES
Áp dụng 3 kỹ thuật: Statistical, Rule-based, Behavioral
"""

import pandas as pd
import numpy as np
import json
import sys
from pathlib import Path

def statistical_detection(df):
    """
    Phương pháp thống kê: Dùng Z-score để tìm outliers
    Rule: value > mean + k*std = anomaly (k=2 cho 95% confidence)
    """
    print("\n" + "="*70)
    print("TECHNIQUE 1: STATISTICAL DETECTION")
    print("="*70)
    print("Phương pháp: Z-score (outlier detection)")
    print("Rule: value > mean + 2*std = anomaly\n")
    
    results = {}
    
    # Query rate anomaly
    mean_qr = df['query_rate'].mean()
    std_qr = df['query_rate'].std()
    threshold_qr = mean_qr + 2 * std_qr
    
    anomaly_qr = df[df['query_rate'] > threshold_qr]
    
    print(f"   [1] Query Rate Anomaly:")
    print(f"       Mean: {mean_qr:.2f} queries/sec")
    print(f"       Std: {std_qr:.2f}")
    print(f"       Threshold: {threshold_qr:.2f}")
    print(f"       Anomalies: {len(anomaly_qr)} IPs")
    
    if len(anomaly_qr) > 0:
        for ip, qr in anomaly_qr.groupby('client_ip')['query_rate'].max().nlargest(5).items():
            print(f"         - IP {ip}: {qr:.2f} q/s")
    
    results['high_query_rate'] = anomaly_qr
    
    # Domain length anomaly
    mean_len = df['subdomain_length'].mean()
    std_len = df['subdomain_length'].std()
    threshold_len = mean_len + 2 * std_len
    
    anomaly_len = df[df['subdomain_length'] > threshold_len]
    
    print(f"\n   [2] Domain Length Anomaly:")
    print(f"       Mean: {mean_len:.1f} chars")
    print(f"       Std: {std_len:.1f}")
    print(f"       Threshold: {threshold_len:.1f}")
    print(f"       Anomalies: {len(anomaly_len)} domains")
    
    results['long_domains'] = anomaly_len
    
    # Entropy anomaly (DGA detection)
    mean_ent = df['domain_entropy'].mean()
    std_ent = df['domain_entropy'].std()
    threshold_ent = mean_ent + 1.5 * std_ent  # k=1.5 vì entropy ít biến động hơn
    
    anomaly_ent = df[df['domain_entropy'] > threshold_ent]
    
    print(f"\n   [3] Entropy Anomaly (DGA detection):")
    print(f"       Mean: {mean_ent:.2f}")
    print(f"       Std: {std_ent:.2f}")
    print(f"       Threshold: {threshold_ent:.2f}")
    print(f"       Anomalies: {len(anomaly_ent)} domains")
    
    results['high_entropy'] = anomaly_ent
    
    return results

def rule_based_detection(df):
    """
    Phương pháp rule-based: Rules cụ thể cho từng attack
    """
    print("\n" + "="*70)
    print("TECHNIQUE 2: RULE-BASED DETECTION")
    print("="*70)
    print("Phương pháp: Định nghĩa rules cụ thể cho từng attack\n")
    
    results = {}
    
    # Rule 1: DNS Burst
    print("   [Rule 1] DNS Burst Detection:")
    print("   Condition: queries_per_sec > 10")
    
    burst = df[df['queries_per_sec'] > 10]
    burst_ips = burst.groupby('client_ip')['queries_per_sec'].max()
    
    print(f"   Result: {len(burst_ips)} IPs detected")
    for ip, qps in burst_ips.nlargest(5).items():
        print(f"     - {ip}: {qps:.0f} q/s")
    
    results['dns_burst'] = burst
    
    # Rule 2: Suspicious Domains
    print("\n   [Rule 2] Suspicious Domain Detection:")
    print("   Condition: suspicious_tld OR suspicious_keyword")
    
    suspicious = df[df['has_suspicious_tld'] | df['has_suspicious_keyword']]
    
    print(f"   Result: {len(suspicious)} suspicious queries")
    print(f"   Unique domains: {suspicious['domain'].nunique()}")
    
    if len(suspicious) > 0:
        print("   Top suspicious domains:")
        for domain in suspicious['domain'].value_counts().head(5).index:
            print(f"     - {domain}")
    
    results['suspicious_domains'] = suspicious
    
    # Rule 3: DNS Tunneling
    print("\n   [Rule 3] DNS Tunneling Detection:")
    print("   Condition: subdomain_length > 30 AND entropy > 3.5")
    
    tunneling = df[(df['subdomain_length'] > 30) & (df['domain_entropy'] > 3.5)]
    
    print(f"   Result: {len(tunneling)} tunneling queries")
    
    if len(tunneling) > 0:
        print("   Sample tunneling domains:")
        for domain in tunneling['domain'].head(3):
            print(f"     - {domain[:60]}...")
    
    results['dns_tunneling'] = tunneling
    
    # Rule 4: DGA Domains
    print("\n   [Rule 4] DGA Domain Detection:")
    print("   Condition: entropy > 3.8 AND consonant_ratio > 0.65")
    
    dga = df[(df['domain_entropy'] > 3.8) & (df['consonant_ratio'] > 0.65)]
    
    print(f"   Result: {len(dga)} DGA-like domains")
    
    if len(dga) > 0:
        print("   Sample DGA domains:")
        for domain in dga['domain'].head(5):
            print(f"     - {domain}")
    
    results['dga_domains'] = dga
    
    # Rule 5: Port Scanning
    print("\n   [Rule 5] Port Scanning Detection:")
    print("   Condition: queries_per_10sec > 20 AND unique domains > 15")
    
    scanning = df[df['queries_per_10sec'] > 20]
    
    if len(scanning) > 0:
        scan_ips = scanning.groupby('client_ip').agg({
            'domain': 'nunique',
            'queries_per_10sec': 'max'
        })
        scan_ips = scan_ips[scan_ips['domain'] > 15]
        
        print(f"   Result: {len(scan_ips)} IPs detected")
        for ip, row in scan_ips.head(5).iterrows():
            print(f"     - {ip}: {row['domain']} domains, {row['queries_per_10sec']:.0f} q/10s")
    else:
        print(f"   Result: 0 IPs detected")
    
    results['port_scanning'] = scanning
    # Rule 6: Botnet Beacons
    print("\n   [Rule 6] Botnet Beacon Detection:")
    print("   Condition: Regular time intervals (3-5 seconds)")
    
    # Filter time_diff trong range 3-5s, bỏ qua NaN
    beacons = df[(df['time_diff'] >= 3.0) & (df['time_diff'] <= 5.0)]
    beacon_ips = beacons.groupby('client_ip').size()
    beacon_ips = beacon_ips[beacon_ips >= 5]  # Ít nhất 5 periodic queries
    
    print(f"   Result: {len(beacon_ips)} IPs with periodic queries")
    for ip, count in beacon_ips.nlargest(5).items():
        print(f"     - {ip}: {count} periodic queries (interval: 3-5s)")
    
    results['botnet_beacons'] = beacons
    
    return results

def behavioral_analysis(df):
    """
    Phương pháp behavioral: Phân tích patterns và deviations
    """
    print("\n" + "="*70)
    print("TECHNIQUE 3: BEHAVIORAL ANALYSIS")
    print("="*70)
    print("Phương pháp: Phân tích patterns và hành vi bất thường\n")
    
    results = {}
    
    # Behavior 1: Traffic Spike
    print("   [Behavior 1] Traffic Spike Analysis:")
    
    timeline = df.groupby('time_window_1min').size()
    mean_traffic = timeline.mean()
    std_traffic = timeline.std()
    
    spikes = timeline[timeline > mean_traffic + 2 * std_traffic]
    
    print(f"   Normal traffic: {mean_traffic:.1f} ± {std_traffic:.1f} queries/min")
    print(f"   Spikes detected: {len(spikes)} time windows")
    
    if len(spikes) > 0:
        for time, count in spikes.nlargest(3).items():
            print(f"     - {time}: {count} queries")
    
    results['traffic_spikes'] = spikes
    
    # Behavior 2: Domain Concentration
    print("\n   [Behavior 2] Domain Concentration Analysis:")
    print("   (Low diversity = possible attack)")
    
    low_diversity = df[df['domain_diversity'] < 0.3]
    low_div_ips = low_diversity.groupby('client_ip')['domain_diversity'].first()
    
    print(f"   IPs with low domain diversity: {len(low_div_ips)}")
    for ip, diversity in low_div_ips.nsmallest(5).items():
        queries = df[df['client_ip'] == ip]['total_queries'].iloc[0]
        print(f"     - {ip}: diversity={diversity:.2f} ({queries:.0f} queries)")
    
    results['low_diversity'] = low_diversity
    
    # Behavior 3: Rare Domains
    print("\n   [Behavior 3] Rare Domain Analysis:")
    print("   (Accessed only 1-2 times = suspicious)")
    
    domain_counts = df['domain'].value_counts()
    rare_domains = domain_counts[domain_counts <= 2]
    
    # Kết hợp: rare + suspicious TLD
    rare_suspicious = df[df['domain'].isin(rare_domains.index) & df['has_suspicious_tld']]
    
    print(f"   Total rare domains: {len(rare_domains)}")
    print(f"   Rare + suspicious: {len(rare_suspicious)}")
    
    if len(rare_suspicious) > 0:
        print("   Sample rare suspicious domains:")
        for domain in rare_suspicious['domain'].unique()[:5]:
            print(f"     - {domain}")
    
    results['rare_domains'] = rare_suspicious
    
    return results

def main():
    print("="*70)
    print("STEP 3: APPLY DETECTION TECHNIQUES")
    print("="*70)
    print()
    
    # Check if features file exists
    features_file = Path('logs/features.csv')
    if not features_file.exists():
        print("❌ Error: logs/features.csv not found!")
        print("   Please run step2_extract_features.py first.")
        return 1
    
    # Load features
    try:
        df = pd.read_csv(features_file)
        print(f" Loaded features: {len(df):,} records, {len(df.columns)} features")
    except Exception as e:
        print(f" Error loading features: {e}")
        return 1
    
    if len(df) == 0:
        print(" Error: Features file is empty!")
        return 1
    
    print()
    
    # Apply 3 techniques
    try:
        stat_results = statistical_detection(df)
        rule_results = rule_based_detection(df)
        behav_results = behavioral_analysis(df)
    except Exception as e:
        print(f"\n Error during detection: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Combine results
    all_results = {
        'statistical': stat_results,
        'rule_based': rule_results,
        'behavioral': behav_results
    }
    
    # Save detection results
    output_dir = Path('results')
    output_dir.mkdir(exist_ok=True)
    
    # Create summary (convert DataFrames to counts)
    summary = {
        'statistical': {name: len(data) for name, data in stat_results.items()},
        'rule_based': {name: len(data) for name, data in rule_results.items()},
        'behavioral': {name: len(data) for name, data in behav_results.items()}
    }
    
    try:
        with open(output_dir / 'detection_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\n Summary saved: results/detection_summary.json")
    except Exception as e:
        print(f"\n  Warning: Could not save summary: {e}")
    
    print("\n" + "="*70)
    print(" DETECTION COMPLETED")
    print("="*70)
    
    # Print final summary
    print("\n DETECTION SUMMARY:")
    
    print("\n   Statistical Methods:")
    for name, count in summary['statistical'].items():
        print(f"     - {name}: {count:,} anomalies")
    
    print("\n   Rule-based Methods:")
    for name, count in summary['rule_based'].items():
        print(f"     - {name}: {count:,} detections")
    
    print("\n   Behavioral Methods:")
    for name, count in summary['behavioral'].items():
        print(f"     - {name}: {count:,} patterns")
    
    print(f"\n Next step: Run step4_visualize.py")
    
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