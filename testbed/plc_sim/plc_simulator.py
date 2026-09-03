import paho.mqtt.client as mqtt
import time
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - PLC_SIM - %(message)s')

BROKER = "edge-broker"
PORT = 1883
TOPIC_TELEMETRY = "factory/plc/telemetry"
TOPIC_COMMAND = "factory/plc/command"

# Simulated physical process state
state = {
    "water_level": 50.0,
    "pump_status": "OFF",
    "setpoint": 80.0
}

def on_connect(client, userdata, flags, rc):
    logging.info(f"Connected to Edge Broker with result code {rc}")
    client.subscribe(TOPIC_COMMAND)

def on_message(client, userdata, msg):
    global state
    try:
        payload = json.loads(msg.payload.decode())
        if "setpoint" in payload:
            logging.warning(f"RECEIVED COMMAND: Changing setpoint from {state['setpoint']} to {payload['setpoint']}")
            state["setpoint"] = float(payload["setpoint"])
    except Exception as e:
        logging.error(f"Failed to parse command: {e}")

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

client.loop_start()

try:
    while True:
        # Simulate physical process.
        # Bang-bang control with an implicit deadband: at level == setpoint neither
        # branch fires, so the pump holds its previous state (intended, not a bug).
        if state["water_level"] < state["setpoint"]:
            state["pump_status"] = "ON"
            state["water_level"] += 2.5
        elif state["water_level"] > state["setpoint"]:
            state["pump_status"] = "OFF"
            state["water_level"] -= 1.0

        # Clamp to the physical floor (level cannot go negative) and round for display.
        state["water_level"] = round(max(0, state["water_level"]), 2)
        
        logging.info(f"Process state: Level={state['water_level']}, Pump={state['pump_status']}, Setpoint={state['setpoint']}")
        client.publish(TOPIC_TELEMETRY, json.dumps(state))
        
        # Check for critical danger (Simulating physical impact)
        if state["water_level"] > 95.0:
            logging.critical("CRITICAL: Water level exceeded safe limits (Tank Overflow Danger!)")
            
        time.sleep(2)
except KeyboardInterrupt:
    logging.info("Stopping PLC simulator")
    client.loop_stop()
    client.disconnect()
