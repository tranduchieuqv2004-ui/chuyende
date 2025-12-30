#!/usr/bin/env python3
"""
Backup kết quả cũ trước khi chạy phân tích mới
"""

import shutil
from pathlib import Path
from datetime import datetime

def backup_results():
    """Backup logs và results"""
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = Path(f'backups/backup_{timestamp}')
    
    print(f" Creating backup...")
    
    # Backup logs
    if Path('logs/parsed_dns.json').exists():
        (backup_dir / 'logs').mkdir(parents=True, exist_ok=True)
        
        for file in ['parsed_dns.json', 'parsed_dhcp.json', 'features.csv']:
            src = Path('logs') / file
            if src.exists():
                dst = backup_dir / 'logs' / file
                shutil.copy(src, dst)
                print(f"   ✓ Backed up: {file}")
    
    # Backup results
    if Path('results').exists():
        shutil.copytree('results', backup_dir / 'results', dirs_exist_ok=True)
        print(f"   ✓ Backed up: results/")
    
    print(f"\n0 Backup saved to: {backup_dir}")
    return backup_dir

if __name__ == '__main__':
    backup_results()