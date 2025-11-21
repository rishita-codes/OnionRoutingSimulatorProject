import sys
import time
import random
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QTextEdit, QGridLayout, QGroupBox, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

import clientmod
import crypto
import networking
import nodes

class SimulationThread(QThread):
    log_signal = pyqtSignal(str)
    update_label_signal = pyqtSignal(str, str)

    def __init__(self, message):
        super().__init__()
        self.message = message

    def run(self):
        client_ip = '192.168.1.10'
        server_ip = '192.168.1.100'

        client = clientmod.Client('client', 10000)
        server = nodes.Node('server', 77777)
        client.data = self.message
        self.log_signal.emit(f"Client message set: {self.message}")

        relnet, client, server, directory, circuit = networking.set_connection(client, server, 5)
        guard = relnet[circuit['GUARD']]
        middle = relnet[circuit['MIDDLE']]
        exitn = relnet[circuit['EXIT']]

        guard_ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        middle_ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        exit_ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

        node_info = {
            'Client': {'IP': client_ip, 'Sender': 'None', 'Receiver': guard_ip},
            'Guard Node': {'IP': guard_ip, 'Sender': client_ip, 'Receiver': middle_ip},
            'Middle Node': {'IP': middle_ip, 'Sender': guard_ip, 'Receiver': exit_ip},
            'Exit Node': {'IP': exit_ip, 'Sender': middle_ip, 'Receiver': server_ip},
            'Server': {'IP': server_ip, 'Sender': exit_ip, 'Receiver': 'None'}
        }

        for node_name, info in node_info.items():
            self.update_label_signal.emit(node_name, f"{node_name}\nIP: {info['IP']}\nSender IP: {info['Sender']}\nReceiver IP: {info['Receiver']}")

        self.log_signal.emit("All node IPs assigned.")

        ct3, rels = clientmod.Client.onion_encrypt(self.message, relnet, circuit, client, server)
        r1, r2, r3 = rels
        self.log_signal.emit("Onion layers encrypted.")

        guard.data = ct3
        ct2 = guard.unbox(r3[0], r3[1], r3[2])
        self.update_label_signal.emit('Guard Node', f"Guard Node\nIP: {guard_ip}\nSender IP: {client_ip}\nReceiver IP: {middle_ip}\nUnboxed:\n{ct2}")
        self.log_signal.emit("Guard node unboxed its layer.")
        time.sleep(0.3)

        middle.data = ct2
        ct1 = middle.unbox(r2[0], r2[1], r2[2])
        self.update_label_signal.emit('Middle Node', f"Middle Node\nIP: {middle_ip}\nSender IP: {guard_ip}\nReceiver IP: {exit_ip}\nUnboxed:\n{ct1}")
        self.log_signal.emit("Middle node unboxed its layer.")
        time.sleep(0.3)

        exitn.data = ct1
        ptn = exitn.unbox(r1[0], r1[1], r1[2])
        self.update_label_signal.emit('Exit Node', f"Exit Node\nIP: {exit_ip}\nSender IP: {middle_ip}\nReceiver IP: {server_ip}\nUnboxed:\n{ptn}")
        self.log_signal.emit("Exit node uncovered plaintext.")
        time.sleep(0.3)

        server.data = ptn.decode()
        self.update_label_signal.emit('Server', f"Server (Receiver)\nIP: {server_ip}\nSender IP: {exit_ip}\nData: {server.data}\n(ACK Sent)")
        self.log_signal.emit("Server received final plaintext. Sending ACK...")
        self.log_signal.emit("ACK → Exit → Middle → Guard → Client (Simulated)")


class OnionGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Onion Routing Simulator GUI")
        self.resize(1000, 800)

        layout = QVBoxLayout()

        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Enter message to send...")
        layout.addWidget(self.input_box)

        self.start_btn = QPushButton("Build Network & Encrypt")
        self.start_btn.clicked.connect(self.start_sim)
        layout.addWidget(self.start_btn)

        grid = QGridLayout()
        layout.addLayout(grid)

        self.client_box = self.make_node_box("Client", width=300, height=150)
        self.guard_box = self.make_node_box("Guard Node", width=300, height=150)
        self.middle_box = self.make_node_box("Middle Node", width=300, height=150)
        self.exit_box = self.make_node_box("Exit Node", width=300, height=150)
        self.server_box = self.make_node_box("Server", width=300, height=150)

        grid.addWidget(self.client_box, 0, 0)
        grid.addWidget(self.guard_box, 0, 1)
        grid.addWidget(self.middle_box, 0, 2)
        grid.addWidget(self.exit_box, 1, 0)
        grid.addWidget(self.server_box, 1, 1)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        self.setLayout(layout)

    def make_node_box(self, title, width=200, height=120):
        box = QGroupBox(title)
        box.setMinimumSize(width, height)
        v = QVBoxLayout()
        lbl = QLabel("Idle")
        lbl.setWordWrap(True)
        v.addWidget(lbl)
        box.setLayout(v)
        box.label = lbl
        return box

    def log_write(self, text):
        self.log.append(text)

    def start_sim(self):
        msg = self.input_box.text().strip()
        if msg == "":
            self.log_write("[!] Enter a message first.")
            return

        self.log.clear()

        self.thread = SimulationThread(msg)
        self.thread.log_signal.connect(self.log_write)
        self.thread.update_label_signal.connect(self.update_node_label)
        self.thread.start()

    def update_node_label(self, node_name, text):
        boxes = {
            'Client': self.client_box,
            'Guard Node': self.guard_box,
            'Middle Node': self.middle_box,
            'Exit Node': self.exit_box,
            'Server': self.server_box
        }
        if node_name in boxes:
            boxes[node_name].label.setText(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = OnionGUI()
    gui.show()
    sys.exit(app.exec())