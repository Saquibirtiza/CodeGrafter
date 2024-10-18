#!/bin/sh

# Start the ERLking system and verify it sends out at least one POI.
# Exits with code 0 on success; 1 on failure.

# This checks for a message from ERLking in the public/aptima/POI/# topic.
# Expects a fresh instance of the common services to be running, and 
# arborway to be loaded into the challenge broker, as it can be analyzed
# quickly enough to verify the system is working within a reasonable time.
# We may later push a custom test challenge.

cat << EOF | docker run -i --rm --network chess_net 077943246560.dkr.ecr.us-east-2.amazonaws.com/integrated_chess_system/uic/erlking/erlking:8.3 bash -c '(/home/utd/scripts/start_chess_daemon.sh > /dev/null 2>&1 &) ; python3'
import logging
import sys
import time
import json
from json import JSONDecodeError
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)

def on_connect(client, userdata, flags, rc):
  # Despite this reference to aptima,
  # this is not dependent on aptima's systems
  client.subscribe("public/aptima/POI/#")

def on_message(client, userdata, msg):
  poi = json.loads(msg.payload)
  if poi['actor']['name'] == 'ERLking':
    # Success; ERLking has produced a POI
    sys.exit(0)

try:
  client = mqtt.Client()
  client.on_message = on_message
  client.on_connect = on_connect
  client.connect("mosquitto", 1883, 60)
  start = time.time()
  while True:
    if time.time() - start > 1500:
      logger.error("Test timed out.")
      sys.exit(1)
    client.loop()
except SystemExit:
  # Calls to exit in the try should not be caught by the handler
  raise
except:
  logger.exception("Test failed with exception.")
  sys.exit(1)
sys.exit(1)
EOF


