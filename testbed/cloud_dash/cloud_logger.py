import paho.mqtt.client as mqtt
import time
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - CLOUD_DASH - %(message)s')

BROKER = "edge-broker"
PORT = 1883
TOPIC_TELEMETRY = "factory/plc/telemetry"

def on_connect(client, userdata, flags, rc):
    logging.info(f"Connected to Edge Broker with result code {rc}")
    client.subscribe(TOPIC_TELEMETRY)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        level = payload.get("water_level", "N/A")
        pump = payload.get("pump_status", "N/A")
        setpoint = payload.get("setpoint", "N/A")
        logging.info(f"Dashboard Update: WaterLevel={level}%, Pump={pump}, Setpoint={setpoint}%")
    except Exception as e:
        logging.error(f"Failed to parse telemetry: {e}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

while True:
    try:
        client.connect(BROKER, PORT, 60)
        break
    except Exception as e:
        logging.info("Waiting for broker...")
        time.sleep(2)

client.loop_forever()
