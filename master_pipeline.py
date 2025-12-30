#!/usr/bin/env python3
"""
MASTER PIPELINE
Chạy toàn bộ quy trình: Parse → Extract → Detect → Visualize
"""

import subprocess
import sys
from pathlib import Path
from datetime import datetime

def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           ANOMALY DETECTION PIPELINE                          ║
║           Parse → Extract → Detect → Visualize                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_requirements():
    """Kiểm tra các file cần thiết"""
    print(" Checking requirements...\n")
    
    required_files = [
        'step1_parse_logs.py',
        'step2_extract_features.py',
        'step3_detect_anomalies.py',
        'step4_visualize.py'
    ]
    
    missing = []
    for f in required_files:
        if not Path(f).exists():
            missing.append(f)
            print(f"   ✗ Missing: {f}")
        else:
            print(f"   ✓ Found: {f}")
    
    if missing:
        print(f"\n Missing {len(missing)} required files!")
        return False
    
    # Check logs directory
    log_dir = Path('logs')
    log_files = list(log_dir.glob('dnsmasq_*.log'))
    
    if not log_files:
        print(f"\n  No log files found in logs/ directory")
        print(f"   Copy logs from server: sudo cp /var/log/dnsmasq.log logs/")
        return False
    
    print(f"\n   ✓ Found {len(log_files)} log file(s)")
    print(f"\n All requirements met!\n")
    return True

def run_step(step_num, script_name, description):
    """Chạy một bước trong pipeline"""
    print("="*70)
    print(f"STEP {step_num}: {description}")
    print("="*70)
    print()
    
    try:
        result = subprocess.run(
            ['python', script_name],
            check=True,
            capture_output=False
        )
        print()
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n Error in {script_name}: {e}")
        return False
    except KeyboardInterrupt:
        print(f"\n Interrupted by user")
        return False

def main():
    print_banner()
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Check requirements
    if not check_requirements():
        print("\n Requirements not met. Please fix and try again.")
        return 1
    
    # Pipeline steps
    steps = [
        (1, 'step1_parse_logs.py', 'PARSE LOGS'),
        (2, 'step2_extract_features.py', 'EXTRACT FEATURES'),
        (3, 'step3_detect_anomalies.py', 'DETECT ANOMALIES'),
        (4, 'step4_visualize.py', 'VISUALIZE RESULTS')
    ]
    
    print("\n" + "="*70)
    print("PIPELINE OVERVIEW")
    print("="*70)
    for num, script, desc in steps:
        print(f"   Step {num}: {desc}")
    print("="*70)
    
    input("\nPress Enter to start pipeline (or Ctrl+C to cancel)...")
    print()
    
    # Run pipeline
    for num, script, desc in steps:
        success = run_step(num, script, desc)
        
        if not success:
            print(f"\n❌ Pipeline failed at step {num}")
            return 1
        
        if num < len(steps):
            print(f"\n{'─'*70}\n")
    
    # Summary
    print("\n" + "="*70)
    print(" PIPELINE COMPLETED SUCCESSFULLY!")
    print("="*70)
    print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n Output files created:")
    print("   Parsed Data:")
    print("     - logs/parsed_dns.json")
    print("     - logs/parsed_dhcp.json")
    print("\n   Features:")
    print("     - logs/features.csv")
    print("\n   Detection Results:")
    print("     - results/detection_summary.json")
    print("\n   Visualizations:")
    print("     - results/1_feature_distributions.png")
    print("     - results/2_anomaly_detection.png")
    print("     - results/3_technique_comparison.png")
    print("     - results/detailed_report.txt")
    
    print("\n Next steps:")
    print("   1. Open PNG files để xem biểu đồ")
    print("   2. Read results/detailed_report.txt")
    print("   3. Analyze results/detection_summary.json")
    
    print("\n" + "="*70)
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  Pipeline interrupted by user")
        sys.exit(1)