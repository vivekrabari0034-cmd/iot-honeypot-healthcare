import json
from collections import Counter
import matplotlib.pyplot as plt
import requests

ips = []
commands = []

# Read log file
with open("var/log/cowrie/cowrie.json") as f:
    for line in f:
        log = json.loads(line)

        if "src_ip" in log:
            ips.append(log["src_ip"])

        if log.get("eventid") == "cowrie.command.input":
            commands.append(log.get("input"))

# Top IPs
top_ips = Counter(ips).most_common(5)

print("Top Attacker IPs:")
for ip, count in top_ips:
    print(ip, count)

print("\nCommands Executed by Attackers:")
for cmd in set(commands):
    print(cmd)

# 🌍 GEOLOCATION PART
print("\nAttacker Locations:")
locations = []

for ip, _ in top_ips:
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        country = response.get("country", "Unknown")
        city = response.get("city", "Unknown")

        print(f"{ip} → {city}, {country}")
        locations.append(f"{ip} → {city}, {country}")

    except:
        print(f"{ip} → Location not found")

# Save report
with open("report.txt", "w") as f:
    f.write("Top Attacker IPs:\n")
    for ip, count in top_ips:
        f.write(f"{ip} {count}\n")

    f.write("\nCommands:\n")
    for cmd in set(commands):
        f.write(f"{cmd}\n")

    f.write("\nLocations:\n")
    for loc in locations:
        f.write(f"{loc}\n")

# Graph
labels = [ip for ip, _ in top_ips]
values = [count for _, count in top_ips]

plt.bar(labels, values)
plt.title("Top Attacker IPs")
plt.xlabel("IP Address")
plt.ylabel("Number of Attacks")
plt.savefig("attacks.png")
plt.show()
