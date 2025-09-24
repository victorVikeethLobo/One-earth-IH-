import csv
import json

THRESHOLDS = {'temperature': 50, 'air_quality': 150, 'water_level_low': 0.1}
alerts = []

with open('sensor_data.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            # Convert string values to floats for comparison
            temp = float(row['temperature'])
            aq = float(row['air_quality'])
            flow = float(row['water_level'])
            
            # Apply IDS rules
            if temp > THRESHOLDS['temperature']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'sensor': row['sensor_id'],
                    'feature': 'temperature',
                    'value': temp,
                    'alert': 'High temp spike',
                    'severity': 'high'
                })
            
            if aq > THRESHOLDS['air_quality']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'sensor': row['sensor_id'],
                    'feature': 'air_quality',
                    'value': aq,
                    'alert': 'Air quality spike',
                    'severity': 'high'
                })
            
            if flow < THRESHOLDS['water_level_low']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'sensor': row['sensor_id'],
                    'feature': 'water_level',
                    'value': flow,
                    'alert': 'Flow suspicious',
                    'severity': 'medium'
                })
        except (ValueError, KeyError) as e:
            # Handle cases where data is missing or not a number
            print(f"Skipping row due to error: {e}")

# Write alerts to a JSON file
with open('alerts.json', 'w') as g:
    json.dump(alerts, g, indent=2)

print(f"Wrote {len(alerts)} alerts to alerts.json.")