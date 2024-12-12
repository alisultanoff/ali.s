import re
import json
import csv
import os
from collections import defaultdict

# Log faylını oxuyun
log_file = "server_logs.txt"  # Fayl adı uyğunlaşdırıldı

# Faylın mövcudluğunu yoxlayın və tam yolunu çap edin
print(f"Fayl yoxlanır: {os.path.abspath(log_file)}")
if not os.path.exists(log_file):
    raise FileNotFoundError(f"Fayl tapılmadı: {os.path.abspath(log_file)}")

with open(log_file, "r") as file:
    logs = file.readlines()

# Regex ifadələri ilə məlumatları çıxarın
log_pattern = r"(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.+?)\] \"(?P<method>\w+) .+?\" (?P<status>\d+)"
matches = [re.search(log_pattern, log) for log in logs]

# Verilənləri toplayın
failed_attempts = defaultdict(int)
log_data = []
for match in matches:
    if match:
        ip = match.group("ip")
        date = match.group("date")
        method = match.group("method")
        status = match.group("status")

        log_data.append({"ip": ip, "date": date, "method": method, "status": int(status)})

        if status == "401":
            failed_attempts[ip] += 1

# 5-dən çox uğursuz giriş cəhdi olan IP-ləri JSON-a yazın
failed_logins = {ip: count for ip, count in failed_attempts.items() if count > 5}
with open("failed_logins.json", "w") as json_file:
    json.dump(failed_logins, json_file, indent=4)

# Çıxarılan IP-ləri və cəhd sayını mətn faylına yazın
with open("log_analysis.txt", "w") as txt_file:
    for ip, count in failed_attempts.items():
        txt_file.write(f"{ip}: {count}\n")

# CSV faylı yaradın
with open("log_analysis.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for log in log_data:
        csv_writer.writerow([log["ip"], log["date"], log["method"], failed_attempts.get(log["ip"], 0)])

# Placeholder for threat intelligence and combined JSON files
threat_ips = []
combined_security_data = {
    "failed_logins": failed_logins,
    "threat_ips": threat_ips
}

# "Threat intelligence" JSON faylı yaradın
with open("threat_ips.json", "w") as json_file:
    json.dump(threat_ips, json_file, indent=4)

# Birləşdirilmiş JSON faylı yaradın
with open("combined_security_data.json", "w") as json_file:
    json.dump(combined_security_data, json_file, indent=4)

print("Analiz tamamlandı və fayllar yaradıldı.")
