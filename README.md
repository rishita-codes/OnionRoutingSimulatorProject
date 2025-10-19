# Onion Routing Simulator for Anonymous and Secure Web Communication

A Python-based simulator demonstrating onion routing for secure and anonymous message transmission. Messages are encrypted in multiple layers (AES + RSA) and routed through a dynamically selected 3-node circuit (GUARD → MIDDLE → EXIT).

---

## Features

- **3-Node Dynamic Circuit:** Each simulation run selects three relay nodes from the network to form the circuit.
- **Layered Encryption:** Messages are encrypted using AES for data and RSA for keys, tags, and nonces.
- **Relay Node Simulation:** Each node unboxes its layer and forwards the message to the next node.
- **Integration Script (`integ.py`):** Demonstrates end-to-end message flow through the circuit.
- **Planned Enhancements:** GUI visualization, server acknowledgement, and attack simulation options.

---

## Requirements

- Python 3.10+  
- PyCryptodome library  

Install PyCryptodome with:
pip install pycryptodome

-Before running the simulator, each node must have its own public and private key files in the correct PEM format:
Public key file: <node_id>publickey.pem
Private key file: <node_id>privatekey.pem

-You can generate the required keys for each node using crypto.py:
from crypto import generate_pub_pri_keys
# Example: generate keys for a node with ID "node1"
generate_pub_pri_keys(prifile="node1privatekey.pem", pubfile="node1publickey.pem")



```bash
pip install pycryptodome
