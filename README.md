# WIFI_LAB – Phân tích hành vi mạng Wi-Fi từ DNS/DHCP log

## 1. Giới thiệu
Dự án phục vụ bài tập lớn môn An toàn hệ thống thông tin.
Mục tiêu là phân tích hành vi thiết bị trong mạng Wi-Fi
thông qua log DNS và DHCP.

## 2. Cấu trúc hệ thống
- step1_parse_logs.py: Chuẩn hóa log thô
- step2_extract_features.py: Trích xuất đặc trưng hành vi
- step3_detect_anomalies.py: Phát hiện bất thường
- step4_visualize.py: Trực quan hóa
- master_pipeline.py: Điều phối pipeline

## 3. Triển khai
```bash
python master_pipeline.py
