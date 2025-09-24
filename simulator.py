import csv
import random
import datetime

# Fields for our simulated sensor data
FIELDS = ['timestamp', 'sensor_id', 'temperature', 'air_quality', 'water_level']

def generate_row(i):
    """
    Generates a single row of sensor data, with a 5% chance of being an "attack"
    """
    ts = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=i)).isoformat()
    base_temp = random.gauss(25, 1)
    base_aq = random.gauss(40, 5)
    base_flow = random.gauss(10, 1)
    
    # Inject an "attack" occasionally
    if random.random() < 0.05:
        return {'timestamp': ts, 'sensor_id': f'S{i%5}', 'temperature': base_temp + random.choice([30, -40]),
                'air_quality': base_aq + random.choice([150, -100]), 'water_level': base_flow * random.choice([0.01, 10])}
    else:
        return {'timestamp': ts, 'sensor_id': f'S{i%5}', 'temperature': round(base_temp, 2),
                'air_quality': round(base_aq, 2), 'water_level': round(base_flow, 2)}

# Write 300 rows of data to a CSV file
with open('sensor_data.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    for i in range(300):
        writer.writerow(generate_row(i))

print("Created sensor_data.csv with simulated data.")