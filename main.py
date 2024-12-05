import re
from collections import defaultdict

def parse_log(file_path):
  with open(file_path, 'r') as file: logs = file.readlines()
  return logs

def count_requests_by_ip(logs):
  ip_count = defaultdict(int)
  for log in logs:
    ip = log.split()[0]
    ip_count[ip] += 1
  return ip_count

def most_frequent_endpoint(logs):
    endpoint_count=defaultdict(int)
    for log in logs: endpoint_count[log.split()[6]]+=1
    most_frequent=max(endpoint_count,key=endpoint_count.get)
    return most_frequent,endpoint_count[most_frequent]

def detect_suspicious_activity(logs,threshold=5):
  failed_attempts = defaultdict(int); suspicious_ips=[]
  for log in logs:
    if "Failed login" in log:
      ip = log.split()[0]
      failed_attempts[ip] += 1
      if failed_attempts[ip] > threshold:
        suspicious_ips.append(ip)
  return suspicious_ips

def main(file_path):
    logs=parse_log(file_path)
    ip_requests=count_requests_by_ip(logs)
    most_frequent, freq_count=most_frequent_endpoint(logs)
    suspicious_ips=detect_suspicious_activity(logs)

    print("Requests per IP address:")
    for ip,count in ip_requests.items(): print(f"{ip}: {count}")

    print("\nMost frequently accessed endpoint:")
    print(f"{most_frequent}: {freq_count} times")

    print("\nSuspicious IPs (possible brute force attacks):")
    for ip in suspicious_ips: print(ip)

if __name__ == "__main__":
    log_file_path='document.log'
    main(log_file_path)
  