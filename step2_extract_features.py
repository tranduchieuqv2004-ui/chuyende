#!/usr/bin/env python3
"""
STEP 2: EXTRACT FEATURES - PHIÊN BẢN HOÀN CHỈNH
Trích xuất các đặc trưng từ parsed data với tự động đếm và validation
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from collections import Counter
import sys

def calculate_entropy(s):
    """Tính entropy của string (measure of randomness)"""
    if not s or len(s) == 0:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs if p > 0)

def extract_domain_features(domain):
    """Trích xuất features từ domain name"""
    
    # Split domain
    parts = domain.split('.')
    subdomain = parts[0] if len(parts) > 0 else ""
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
    tld = parts[-1] if len(parts) > 0 else ""
    
    features = {
        # Length features
        'domain_length': len(domain),
        'subdomain_length': len(subdomain),
        'num_dots': domain.count('.'),
        'num_hyphens': domain.count('-'),
        
        # Character features
        'num_digits': sum(c.isdigit() for c in domain),
        'num_uppercase': sum(c.isupper() for c in domain),
        'digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0,
        
        # Entropy (randomness)
        'domain_entropy': calculate_entropy(subdomain),
        
        # Vowel/Consonant ratio
        'vowel_count': sum(1 for c in subdomain.lower() if c in 'aeiou'),
        'consonant_count': sum(1 for c in subdomain.lower() if c in 'bcdfghjklmnpqrstvwxyz'),
        'consonant_ratio': sum(1 for c in subdomain.lower() if c in 'bcdfghjklmnpqrstvwxyz') / len(subdomain) if len(subdomain) > 0 else 0,
        
        # Domain components
        'base_domain': base_domain,
        'tld': tld,
        
        # Suspicious indicators
        'has_suspicious_tld': tld in ['ru', 'xyz', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'top', 'club'],
        'has_suspicious_keyword': any(kw in domain.lower() for kw in ['malware', 'phishing', 'botnet', 'c2', 'trojan', 'evil', 'hack']),
    }
    
    return features

def extract_temporal_features(df):
    """Trích xuất features về thời gian"""
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')
    
    # Time-based features
    df['hour'] = df['timestamp'].dt.hour
    df['minute'] = df['timestamp'].dt.minute
    df['second'] = df['timestamp'].dt.second
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Time windows
    df['time_window_1s'] = df['timestamp'].dt.floor('1s')
    df['time_window_10s'] = df['timestamp'].dt.floor('10s')
    df['time_window_1min'] = df['timestamp'].dt.floor('1min')
    
    return df

def extract_behavioral_features(df):
    """Trích xuất features về hành vi"""
    
    print("   Extracting behavioral features...")
    
    # Per-IP features
    ip_features = df.groupby('client_ip').agg({
        'domain': ['count', 'nunique'],  # Total queries, unique domains
        'timestamp': lambda x: (x.max() - x.min()).total_seconds()  # Duration
    }).reset_index()
    
    ip_features.columns = ['client_ip', 'total_queries', 'unique_domains', 'duration_seconds']
    
    # Query rate
    ip_features['query_rate'] = ip_features['total_queries'] / (ip_features['duration_seconds'] + 1)
    
    # Domain diversity
    ip_features['domain_diversity'] = ip_features['unique_domains'] / ip_features['total_queries']
    
    # Merge back to main df
    df = df.merge(ip_features[['client_ip', 'total_queries', 'query_rate', 'domain_diversity']], 
                  on='client_ip', how='left')
    
    # Time interval between queries (same IP)
    df = df.sort_values(['client_ip', 'timestamp'])
    df['time_diff'] = df.groupby('client_ip')['timestamp'].diff().dt.total_seconds()
    
    return df

def print_feature_summary(original_columns, domain_features, temporal_features, 
                         behavioral_features, statistical_features, df):
    """In summary chi tiết về features đã trích xuất"""
    
    print(f"\n   ✓ Extracted {len(df.columns)} total columns")
    
    # Calculate counts
    num_original = len(original_columns)
    num_domain = len(domain_features)
    num_temporal = len(temporal_features)
    num_behavioral = len(behavioral_features)
    num_statistical = len(statistical_features)
    num_new = len(df.columns) - num_original
    
    # Main summary
    print("\n    Feature Categories:")
    print(f"      - Original columns: {num_original}")
    print(f"      - Domain features: {num_domain}")
    print(f"      - Temporal features: {num_temporal}")
    print(f"      - Behavioral features: {num_behavioral}")
    print(f"      - Statistical features: {num_statistical}")
    print(f"      {'─'*35}")
    print(f"      Total columns: {len(df.columns)}")
    print(f"      New features added: {num_new}")
    
    # Detailed feature names
    print("\n    Feature Details:")
    
    # Domain features
    print(f"\n      Domain features ({num_domain}):")
    for i, feat in enumerate(sorted(domain_features), 1):
        print(f"        {i:2d}. {feat}")
    
    # Temporal features
    print(f"\n      Temporal features ({num_temporal}):")
    for i, feat in enumerate(sorted(temporal_features), 1):
        print(f"        {i:2d}. {feat}")
    
    # Behavioral features
    print(f"\n      Behavioral features ({num_behavioral}):")
    for i, feat in enumerate(sorted(behavioral_features), 1):
        print(f"        {i:2d}. {feat}")
    
    # Statistical features
    print(f"\n      Statistical features ({num_statistical}):")
    for i, feat in enumerate(sorted(statistical_features), 1):
        print(f"        {i:2d}. {feat}")
    
    # Validation
    print("\n    Validation:")
    expected = {
        'Domain': (num_domain, 15),
        'Temporal': (num_temporal, 7),
        'Behavioral': (num_behavioral, 6),
        'Statistical': (num_statistical, 2)
    }
    
    all_correct = True
    for category, (actual, expected_count) in expected.items():
        if actual == expected_count:
            print(f"      ✓ {category}: {actual} features (expected {expected_count})")
        else:
            print(f"      ✗ {category}: {actual} features (expected {expected_count}) ⚠️")
            all_correct = False
    
    if not all_correct:
        print("\n        WARNING: Feature count mismatch detected!")
        print("      This might indicate missing or extra features.")
    else:
        print("\n      ✓ All feature counts match expected values!")

def print_sample_features(df):
    """In sample features từ first record"""
    
    print("\n    Sample features for first query:")
    sample = df.iloc[0]
    
    # Basic info
    print(f"\n      Basic Information:")
    print(f"        Domain: {sample['domain']}")
    print(f"        Client IP: {sample['client_ip']}")
    print(f"        Timestamp: {sample['timestamp']}")
    
    # Domain features
    print(f"\n      Domain Features:")
    print(f"        Length: {sample['domain_length']} chars")
    print(f"        Subdomain length: {sample['subdomain_length']} chars")
    print(f"        Entropy: {sample['domain_entropy']:.3f}")
    print(f"        Consonant ratio: {sample['consonant_ratio']:.3f}")
    print(f"        TLD: .{sample['tld']}")
    print(f"        Suspicious TLD: {'Yes' if sample['has_suspicious_tld'] else 'No'}")
    print(f"        Suspicious keyword: {'Yes' if sample['has_suspicious_keyword'] else 'No'}")
    
    # Behavioral features
    print(f"\n      Behavioral Features:")
    print(f"        Query rate: {sample['query_rate']:.3f} queries/sec")
    print(f"        Domain diversity: {sample['domain_diversity']:.3f}")
    print(f"        Total queries (this IP): {sample['total_queries']:.0f}")
    
    # Statistical features
    print(f"\n      Statistical Features:")
    print(f"        Queries per second: {sample['queries_per_sec']:.0f}")
    print(f"        Queries per 10 sec: {sample['queries_per_10sec']:.0f}")

def print_dataset_statistics(df):
    """In thống kê tổng quan về dataset"""
    
    print("\n    Dataset Statistics:")
    print(f"\n      General:")
    print(f"        Total records: {len(df):,}")
    print(f"        Unique IPs: {df['client_ip'].nunique()}")
    print(f"        Unique domains: {df['domain'].nunique()}")
    print(f"        Time span: {(df['timestamp'].max() - df['timestamp'].min()).total_seconds():.0f} seconds")
    
    print(f"\n      Domain Statistics:")
    print(f"        Avg domain length: {df['domain_length'].mean():.1f} chars")
    print(f"        Avg entropy: {df['domain_entropy'].mean():.3f}")
    print(f"        Suspicious TLD rate: {df['has_suspicious_tld'].mean()*100:.1f}%")
    print(f"        Suspicious keyword rate: {df['has_suspicious_keyword'].mean()*100:.1f}%")
    
    print(f"\n      Behavioral Statistics:")
    print(f"        Avg query rate: {df['query_rate'].mean():.3f} q/s")
    print(f"        Avg domain diversity: {df['domain_diversity'].mean():.3f}")
    print(f"        Max burst (per sec): {df['queries_per_sec'].max():.0f} queries")
    print(f"        Max burst (per 10sec): {df['queries_per_10sec'].max():.0f} queries")

def extract_all_features():
    """Main function: Extract tất cả features"""
    
    print("="*70)
    print("STEP 2: EXTRACT FEATURES")
    print("="*70)
    print()
    
    # Check if parsed data exists
    parsed_file = Path('logs/parsed_dns.json')
    if not parsed_file.exists():
        print(" Error: logs/parsed_dns.json not found!")
        print("   Please run step1_parse_logs.py first.")
        return None
    
    # Load parsed data
    try:
        with open(parsed_file, 'r') as f:
            dns_data = json.load(f)
    except Exception as e:
        print(f" Error loading parsed data: {e}")
        return None
    
    df = pd.DataFrame(dns_data)
    print(f" Loaded {len(df)} DNS queries")
    
    if len(df) == 0:
        print(" Error: No data in parsed file!")
        return None
    
    print()
    
    # Track original columns
    original_columns = set(df.columns)
    
    # 1. Domain features
    print("   [1/4] Extracting domain features...")
    try:
        domain_features_df = df['domain'].apply(extract_domain_features).apply(pd.Series)
        df = pd.concat([df, domain_features_df], axis=1)
        domain_feature_names = set(domain_features_df.columns)
        print(f"         ✓ Added {len(domain_feature_names)} domain features")
    except Exception as e:
        print(f"         ✗ Error: {e}")
        return None
    
    # 2. Temporal features
    print("   [2/4] Extracting temporal features...")
    try:
        columns_before = set(df.columns)
        df = extract_temporal_features(df)
        temporal_feature_names = set(df.columns) - columns_before
        print(f"         ✓ Added {len(temporal_feature_names)} temporal features")
    except Exception as e:
        print(f"         ✗ Error: {e}")
        return None
    
    # 3. Behavioral features
    print("   [3/4] Extracting behavioral features...")
    try:
        columns_before = set(df.columns)
        df = extract_behavioral_features(df)
        behavioral_feature_names = set(df.columns) - columns_before
        print(f"         ✓ Added {len(behavioral_feature_names)} behavioral features")
    except Exception as e:
        print(f"         ✗ Error: {e}")
        return None
    
    # 4. Statistical features
    print("   [4/4] Computing statistical features...")
    try:
        columns_before = set(df.columns)
        
        # Queries per time window
        burst_1s = df.groupby(['time_window_1s', 'client_ip']).size().reset_index(name='queries_per_sec')
        burst_10s = df.groupby(['time_window_10s', 'client_ip']).size().reset_index(name='queries_per_10sec')
        
        df = df.merge(burst_1s, on=['time_window_1s', 'client_ip'], how='left')
        df = df.merge(burst_10s, on=['time_window_10s', 'client_ip'], how='left')
        
        statistical_feature_names = set(df.columns) - columns_before
        print(f"         ✓ Added {len(statistical_feature_names)} statistical features")
    except Exception as e:
        print(f"         ✗ Error: {e}")
        return None
    
    # Save features
    try:
        output_file = Path('logs/features.csv')
        df.to_csv(output_file, index=False)
        print(f"\n    Saved: {output_file}")
        print(f"      File size: {output_file.stat().st_size / 1024:.1f} KB")
    except Exception as e:
        print(f"   ✗ Error saving features: {e}")
        return None
    
    # Print summaries
    print_feature_summary(original_columns, domain_feature_names, temporal_feature_names,
                         behavioral_feature_names, statistical_feature_names, df)
    
    print_sample_features(df)
    
    print_dataset_statistics(df)
    
    print("\n" + "="*70)
    print(" FEATURE EXTRACTION COMPLETED")
    print("="*70)
    print("\n Next step: Run step3_detect_anomalies.py")
    
    return df

if __name__ == '__main__':
    try:
        df = extract_all_features()
        if df is None:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)