import re
import matplotlib.pyplot as plt
from datetime import datetime

log_file = 'cloud-dash-logs.txt'
times = []
water_levels = []
setpoints = []

# cloud-dash  | ...Z 2026-07-30 17:32:53,375 - CLOUD_DASH - Dashboard Update: WaterLevel=55.0%, Pump=ON, Setpoint=80.0%
# Capture the application log timestamp so the x-axis is real elapsed time, not a synthetic step.
regex = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) .*WaterLevel=([0-9.]+).*Setpoint=([0-9.]+)')

try:
    with open(log_file, 'r', encoding='utf-16') as f:
        lines = f.readlines()
except Exception:
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

t0 = None
attack_t = None
for line in lines:
    m = regex.search(line)
    if m:
        ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S,%f')
        wl = float(m.group(2))
        sp = float(m.group(3))
        if t0 is None:
            t0 = ts
        t = (ts - t0).total_seconds()
        water_levels.append(wl)
        setpoints.append(sp)

        # Attack sets setpoint to 120.0 or 0 (anomalous)
        if sp >= 100.0 and attack_t is None:
            attack_t = t

        times.append(t)

plt.figure(figsize=(10, 5))
plt.plot(times, water_levels, label='Water Level (PV)', color='blue', linewidth=2)
plt.plot(times, setpoints, label='Setpoint (SP)', color='red', linestyle='--', linewidth=2)

if attack_t is not None:
    plt.axvline(x=attack_t, color='black', linestyle=':', label='T0831 Attack Injected')
    
# Add overflow-hazard threshold line (matches plc_sim critical threshold)
plt.axhline(y=95.0, color='orange', linestyle='-', alpha=0.5, label='Overflow-Hazard Threshold (95%)')

plt.title('Boundary B3 Compromise: Manipulation of Control (T0831)')
plt.xlabel('Time (s)')
plt.ylabel('Tank Level (%)')
plt.legend(loc='upper left')
plt.grid(True)
plt.tight_layout()
plt.savefig('attack_plot.pdf')
print(f"Generated attack_plot.pdf with {len(times)} data points.")
