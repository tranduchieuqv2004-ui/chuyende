#!/usr/bin/env python3
"""
STEP 1: PARSE LOGS
Đọc raw logs và chuyển thành structured JSON
"""

import re
import json
from datetime import datetime
from pathlib import Path
import sys

def parse_dnsmasq_log(log_file):
    """Parse dnsmasq log file thành structured data"""
    
    print(f" STEP 1: PARSING LOGS")
    print(f"   File: {log_file}")
    print(f"   Size: {log_file.stat().st_size / 1024:.1f} KB")
    
    if log_file.stat().st_size == 0:
        print("\n     WARNING: Log file is empty!")
        return [], []
    
    dns_queries = []
    dhcp_events = []
    
    # Regex patterns - flexible để match nhiều format
    # \w+ +\d+ : match "Dec  26" hoặc "Dec 26" (spaces khác nhau)
    # .*? : non-greedy matching (faster)
    # \w+ : match cả "A", "AAAA", "a", "aaaa"
    dns_pattern = r'(\w+ +\d+ +\d+:\d+:\d+).*?query\[(\w+)\]\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)'
    dhcp_pattern = r'(\w+ +\d+ +\d+:\d+:\d+).*?DHCP(\w+)\(.*?\)\s+(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)'
    
    current_year = datetime.now().year
    
    dns_count = 0
    dhcp_count = 0
    total_lines = 0
    parse_errors = 0
    skipped_lines = 0
    
    print(f"\n   Parsing...")
    
    try:
        # Stream file thay vì load toàn bộ (tốt cho file lớn)
        with open(log_file, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                
                # Progress indicator cho file lớn
                if line_num % 1000 == 0:
                    print(f"      Processed {line_num} lines...", end='\r')
                
                if not line.strip():
                    skipped_lines += 1
                    continue
                
                # Parse DNS query
                dns_match = re.search(dns_pattern, line)
                if dns_match:
                    try:
                        timestamp_str = dns_match.group(1).strip()
                        query_type = dns_match.group(2).upper()  # Normalize
                        domain = dns_match.group(3)
                        client_ip = dns_match.group(4)
                        
                        # Try 2 timestamp formats: "Dec 26" và "December 26"
                        try:
                            timestamp = datetime.strptime(
                                f"{current_year} {timestamp_str}", 
                                "%Y %b %d %H:%M:%S"
                            )
                        except ValueError:
                            timestamp = datetime.strptime(
                                f"{current_year} {timestamp_str}", 
                                "%Y %B %d %H:%M:%S"
                            )
                        
                        dns_queries.append({
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'client_ip': client_ip,
                            'domain': domain,
                            'query_type': query_type
                        })
                        dns_count += 1
                    except Exception as e:
                        parse_errors += 1
                        # Chỉ hiển thị 5 lỗi đầu để tránh spam
                        if parse_errors <= 5:
                            print(f"\n     Parse error at line {line_num}: {str(e)[:50]}")
                        continue
                
                # Parse DHCP event
                dhcp_match = re.search(dhcp_pattern, line)
                if dhcp_match:
                    try:
                        timestamp_str = dhcp_match.group(1).strip()
                        event_type = dhcp_match.group(2).upper()
                        client_ip = dhcp_match.group(3)
                        client_mac = dhcp_match.group(4)
                        
                        try:
                            timestamp = datetime.strptime(
                                f"{current_year} {timestamp_str}", 
                                "%Y %b %d %H:%M:%S"
                            )
                        except ValueError:
                            timestamp = datetime.strptime(
                                f"{current_year} {timestamp_str}", 
                                "%Y %B %d %H:%M:%S"
                            )
                        
                        dhcp_events.append({
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'event_type': f'DHCP{event_type}',
                            'client_ip': client_ip,
                            'client_mac': client_mac
                        })
                        dhcp_count += 1
                    except Exception as e:
                        parse_errors += 1
                        continue
        
        print(" " * 80, end='\r')
        
    except Exception as e:
        print(f"\n    Error reading file: {e}")
        return [], []
    
    print(f"\n    Parsing Statistics:")
    print(f"      Total lines: {total_lines:,}")
    print(f"      Empty/skipped lines: {skipped_lines:,}")
    print(f"      Parse errors: {parse_errors:,}")
    print(f"      ✓ DNS queries: {dns_count:,}")
    print(f"      ✓ DHCP events: {dhcp_count:,}")
    
    # Warning nếu không parse được data
    if dns_count == 0 and dhcp_count == 0:
        print(f"\n     WARNING: No DNS/DHCP data parsed!")
        print(f"      This might indicate:")
        print(f"        - Log format doesn't match expected pattern")
        print(f"        - Log file contains no DNS/DHCP entries")
        
        # Show sample lines để debug
        print(f"\n    Sample log lines (first 3):")
        try:
            with open(log_file, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= 3:
                        break
                    if line.strip():
                        print(f"      {i+1}: {line.strip()[:80]}")
        except:
            pass
    
    # Save parsed data
    output_dir = Path('logs')
    output_dir.mkdir(exist_ok=True)
    
    try:
        dns_output = output_dir / 'parsed_dns.json'
        with open(dns_output, 'w', encoding='utf-8') as f:
            json.dump(dns_queries, f, indent=2, ensure_ascii=False)
        print(f"\n    Saved DNS: {dns_output}")
        print(f"      Records: {len(dns_queries):,}")
        print(f"      Size: {dns_output.stat().st_size / 1024:.1f} KB")
        
        dhcp_output = output_dir / 'parsed_dhcp.json'
        with open(dhcp_output, 'w', encoding='utf-8') as f:
            json.dump(dhcp_events, f, indent=2, ensure_ascii=False)
        print(f"\n   💾 Saved DHCP: {dhcp_output}")
        print(f"      Records: {len(dhcp_events):,}")
        print(f"      Size: {dhcp_output.stat().st_size / 1024:.1f} KB")
        
    except Exception as e:
        print(f"\n    Error saving output: {e}")
        return [], []
    
    # Summary statistics
    if dns_count > 0:
        print(f"\n    DNS Summary:")
        unique_ips = len(set(q['client_ip'] for q in dns_queries))
        unique_domains = len(set(q['domain'] for q in dns_queries))
        
        # Đếm từng loại query (A, AAAA, TXT, ...)
        query_types = {}
        for q in dns_queries:
            qt = q['query_type']
            query_types[qt] = query_types.get(qt, 0) + 1
        
        print(f"      Unique client IPs: {unique_ips}")
        print(f"      Unique domains: {unique_domains}")
        print(f"      Query types:")
        for qt, count in sorted(query_types.items(), key=lambda x: x[1], reverse=True):
            print(f"        {qt}: {count:,} ({count/dns_count*100:.1f}%)")
    
    if dhcp_count > 0:
        print(f"\n    DHCP Summary:")
        unique_macs = len(set(e['client_mac'] for e in dhcp_events))
        unique_ips = len(set(e['client_ip'] for e in dhcp_events))
        
        event_types = {}
        for e in dhcp_events:
            et = e['event_type']
            event_types[et] = event_types.get(et, 0) + 1
        
        print(f"      Unique MAC addresses: {unique_macs}")
        print(f"      Unique IP addresses: {unique_ips}")
        print(f"      Event types:")
        for et, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            print(f"        {et}: {count:,}")
    
    return dns_queries, dhcp_events

def validate_log_file(log_file):
    """Kiểm tra log file có hợp lệ không trước khi parse"""
    
    if not log_file.exists():
        print(f"    File not found: {log_file}")
        return False
    
    if not log_file.is_file():
        print(f"    Not a file: {log_file}")
        return False
    
    if log_file.stat().st_size == 0:
        print(f"     File is empty: {log_file}")
        return False
    
    try:
        with open(log_file, 'r') as f:
            f.read(100)
    except Exception as e:
        print(f"    Cannot read file: {e}")
        return False
    
    return True

def main():
    print("="*70)
    print("STEP 1: PARSE LOGS")
    print("="*70)
    print()
    
    log_dir = Path('logs')
    
    if not log_dir.exists():
        print(" logs/ directory not found!")
        print("   Creating logs/ directory...")
        log_dir.mkdir(exist_ok=True)
        print("   Please copy log files to logs/ directory")
        return 1
    
    log_files = list(log_dir.glob('dnsmasq_*.log'))
    
    if not log_files:
        print(" No log files found!")
        print("   Looking for: logs/dnsmasq_*.log")
        print("\n    To get logs from server:")
        print("      sudo cp /var/log/dnsmasq.log logs/dnsmasq_$(date +%Y%m%d_%H%M%S).log")
        return 1
    
    print(f"✓ Found {len(log_files)} log file(s)")
    
    if len(log_files) > 1:
        print("\n   Available log files:")
        for i, lf in enumerate(sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True), 1):
            mtime = datetime.fromtimestamp(lf.stat().st_mtime)
            size = lf.stat().st_size / 1024
            print(f"      {i}. {lf.name} ({size:.1f} KB, {mtime.strftime('%Y-%m-%d %H:%M:%S')})")
    
    # Chọn file mới nhất (modified time)
    latest_log = max(log_files, key=lambda p: p.stat().st_mtime)
    print(f"\n   Using: {latest_log.name}")
    
    if not validate_log_file(latest_log):
        return 1
    
    print()
    
    dns_queries, dhcp_events = parse_dnsmasq_log(latest_log)
    
    if len(dns_queries) == 0 and len(dhcp_events) == 0:
        print("\n" + "="*70)
        print("  PARSING COMPLETED WITH NO DATA")
        print("="*70)
        print("\n   Please check:")
        print("   1. Log file format matches dnsmasq output")
        print("   2. Log contains DNS query or DHCP event entries")
        print("   3. dnsmasq logging is enabled")
        return 1
    else:
        print("\n" + "="*70)
        print(" PARSING COMPLETED SUCCESSFULLY")
        print("="*70)
        print(f"\n   Next step: Run step2_extract_features.py")
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