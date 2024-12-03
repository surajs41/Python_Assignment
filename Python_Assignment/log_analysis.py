import csv
from collections import Counter, defaultdict

def analyze_log(file_path, threshold=10):
    ip_request_counts = Counter()
    endpoint_counts = Counter()
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()

            ip_address = parts[0]
            ip_request_counts[ip_address] += 1
 
            endpoint = parts[6]  
            endpoint_counts[endpoint] += 1
            
  
            if parts[-1].strip('"') == "Invalid credential" or parts[8] == "401":
                failed_login_attempts[ip_address] += 1

    most_accessed_endpoint = endpoint_counts.most_common(1)[0]

    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_request_counts.most_common():
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity is Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity was detected.")

    with open('log_analysis_results.csv','w',newline='') as csvfile:
        csv_writer = csv.writer(csvfile)


        csv_writer.writerow(["Requests per IP"])
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_counts.items():
         csv_writer.writerow([ip, count])
        csv_writer.writerow([])
        csv_writer.writerow(["Most Accessed Endpoint"])
        csv_writer.writerow(["Endpoint", "Access Count"])
        csv_writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        csv_writer.writerow([])
        csv_writer.writerow(["Suspicious Activity"])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            csv_writer.writerow([ip, count])


analyze_log("sample.log")
