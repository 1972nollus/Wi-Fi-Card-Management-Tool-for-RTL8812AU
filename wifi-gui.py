#!/usr/bin/env python3
import sys
import subprocess
import threading
import signal
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QLabel, 
                             QGroupBox, QScrollArea, QMessageBox, QComboBox,
                             QFrame, QSizePolicy)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QObject
from PyQt5.QtGui import QTextCursor

# Signal class for thread-safe output
class OutputSignal(QObject):
    output_signal = pyqtSignal(str)

class WiFiToolGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interface = "wlan1"
        self.scan_process = None
        self.scan_thread = None
        self.scan_running = False
        self.wash_process = None
        self.wash_thread = None
        self.wash_running = False
        self.output_signal = OutputSignal()
        self.output_signal.output_signal.connect(self.append_output)
        self.initUI()
        self.refresh_interfaces()
        
    def initUI(self):
        self.setWindowTitle("Wi-Fi Card Management Tool")
        self.setGeometry(100, 100, 1000, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Left panel - controls
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        left_panel.setFixedWidth(350)
        
        # Right panel - output
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        
        # Interface selection
        interface_group = QGroupBox("Network Interface Selection")
        interface_group.setStyleSheet("QGroupBox { color: #3498db; font-weight: bold; }")
        interface_layout = QVBoxLayout()
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Interfaces")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        refresh_btn.setStyleSheet("background-color: #3498db; color: white; font-weight: bold; padding: 8px;")
        interface_layout.addWidget(refresh_btn)
        
        # Interface dropdown
        interface_layout.addWidget(QLabel("Select Network Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.currentTextChanged.connect(self.interface_changed)
        self.interface_combo.setStyleSheet("background-color: #2c3e50; color: white; padding: 5px;")
        interface_layout.addWidget(self.interface_combo)
        
        # Current interface info
        self.interface_info = QLabel("No interface selected")
        self.interface_info.setWordWrap(True)
        self.interface_info.setStyleSheet("background-color: #34495e; color: #ecf0f1; padding: 10px; border: 1px solid #2c3e50; border-radius: 5px;")
        interface_layout.addWidget(self.interface_info)
        
        interface_group.setLayout(interface_layout)
        left_layout.addWidget(interface_group)
        
        # Create button groups
        self.create_mode_buttons(left_layout)
        self.create_tool_buttons(left_layout)
        self.create_utility_buttons(left_layout)
        
        # Output console with stop button container
        output_container = QWidget()
        output_layout = QVBoxLayout(output_container)
        
        output_group = QGroupBox("Command Output")
        output_group.setStyleSheet("QGroupBox { color: #3498db; font-weight: bold; }")
        group_layout = QVBoxLayout()
        
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; font-family: monospace;")
        group_layout.addWidget(self.output_console)
        
        # Stop button container
        self.stop_button_container = QWidget()
        self.stop_button_layout = QHBoxLayout(self.stop_button_container)
        self.stop_button_layout.setContentsMargins(0, 5, 0, 0)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 5px;")
        self.stop_scan_btn.hide()
        
        self.stop_wash_btn = QPushButton("Stop WPS Scan")
        self.stop_wash_btn.clicked.connect(self.stop_wash)
        self.stop_wash_btn.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 5px;")
        self.stop_wash_btn.hide()
        
        self.stop_button_layout.addWidget(self.stop_scan_btn)
        self.stop_button_layout.addWidget(self.stop_wash_btn)
        self.stop_button_layout.addStretch()
        
        group_layout.addWidget(self.stop_button_container)
        output_group.setLayout(group_layout)
        
        output_layout.addWidget(output_group)
        right_layout.addWidget(output_container)
        
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)
        
        self.append_output("Wi-Fi Card Management Tool Started")
        
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces"""
        self.interface_combo.clear()
        
        # Get all wireless interfaces
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split('Interface ')[1].strip()
                    interfaces.append(iface)
            
            if interfaces:
                self.interface_combo.addItems(interfaces)
                # Try to select wlan1 by default, or first available
                if "wlan1" in interfaces:
                    self.interface_combo.setCurrentText("wlan1")
                else:
                    self.interface_combo.setCurrentIndex(0)
            else:
                self.interface_combo.addItem("No wireless interfaces found")
                self.interface_info.setText("No wireless interfaces detected. Check your Wi-Fi card.")
                
        except Exception as e:
            self.interface_combo.addItem("Error detecting interfaces")
            self.interface_info.setText(f"Error: {str(e)}")
    
    def interface_changed(self, interface):
        """Handle interface selection change"""
        if interface and "No wireless" not in interface and "Error" not in interface:
            self.interface = interface
            self.setWindowTitle(f"Wi-Fi Card Management Tool - {self.interface}")
            self.update_interface_info()
    
    def update_interface_info(self):
        """Update information about the selected interface"""
        try:
            # Get interface type
            type_result = subprocess.run(["iw", "dev", self.interface, "info"], 
                                       capture_output=True, text=True, timeout=5)
            interface_type = "Unknown"
            for line in type_result.stdout.split('\n'):
                if 'type' in line:
                    interface_type = line.split('type ')[1].strip()
                    break
            
            # Get MAC address
            mac_addr = "Unknown"
            try:
                with open(f"/sys/class/net/{self.interface}/address", "r") as f:
                    mac_addr = f.read().strip()
            except:
                pass
            
            # Get driver info
            driver_result = subprocess.run(["ethtool", "-i", self.interface], 
                                         capture_output=True, text=True, timeout=5)
            driver_info = "Unknown"
            for line in driver_result.stdout.split('\n'):
                if 'driver:' in line:
                    driver_info = line.split('driver:')[1].strip()
                    break
            
            info_text = f"Interface: {self.interface}\nType: {interface_type}\nMAC: {mac_addr}\nDriver: {driver_info}"
            self.interface_info.setText(info_text)
            
        except Exception as e:
            self.interface_info.setText(f"Error getting interface info: {str(e)}")
    
    def create_mode_buttons(self, layout):
        group = QGroupBox("Mode Management")
        group.setStyleSheet("QGroupBox { color: #e74c3c; font-weight: bold; }")
        group_layout = QVBoxLayout()
        buttons = [
            ("Kill Conflicting Processes", self.kill_processes),
            ("Set MANAGED Mode", self.set_managed),
            ("Set MONITOR Mode", self.set_monitor),
            ("Set TX Power to 30 dBm", self.set_txpower),
            ("Change MAC Address", self.change_mac)
        ]
        
        for text, slot in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            btn.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold; padding: 8px;")
            group_layout.addWidget(btn)
            
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def create_tool_buttons(self, layout):
        group = QGroupBox("Testing Tools")
        group.setStyleSheet("QGroupBox { color: #2ecc71; font-weight: bold; }")
        group_layout = QVBoxLayout()
        
        buttons = [
            ("Scan Networks (airodump-ng)", self.scan_networks),
            ("Test Packet Injection", self.test_injection),
            ("Test WPS Networks (wash)", self.test_wash)
        ]
        
        for text, slot in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            btn.setStyleSheet("background-color: #2ecc71; color: white; font-weight: bold; padding: 8px;")
            group_layout.addWidget(btn)
            
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def create_utility_buttons(self, layout):
        group = QGroupBox("Utilities")
        group.setStyleSheet("QGroupBox { color: #f39c12; font-weight: bold; }")
        group_layout = QVBoxLayout()
  
        
        buttons = [
            ("Check Current Settings", self.show_settings),
            ("Restart NetworkManager", self.restart_networkmanager),
            ("Clear Output", self.clear_output)
        ]
        
        for text, slot in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            btn.setStyleSheet("background-color: #f39c12; color: white; font-weight: bold; padding: 8px;")
            group_layout.addWidget(btn)
            
        group.setLayout(group_layout)
        layout.addWidget(group)
        
        # Exit button
        exit_btn = QPushButton("Exit")
        exit_btn.clicked.connect(self.close)
        exit_btn.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 8px;")
        layout.addWidget(exit_btn)
    
    def run_command(self, command, shell=False, timeout=30):
        """Run a command and return the output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def append_output(self, text):
        """Append text to the output console"""
        self.output_console.moveCursor(QTextCursor.End)
        self.output_console.insertPlainText(text + "\n")
        self.output_console.ensureCursorVisible()
    
    def kill_processes(self):
        self.append_output(f"\n=== Killing conflicting processes on {self.interface} ===")
        output = self.run_command(["airmon-ng", "check", "kill"])
        self.append_output(output)
    
    def set_managed(self):
        self.append_output(f"\n=== Setting MANAGED mode on {self.interface} ===")
        commands = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "type", "managed"],
            ["ip", "link", "set", self.interface, "up"],
            ["systemctl", "restart", "NetworkManager"]
        ]
        
        for cmd in commands:
            output = self.run_command(cmd)
            self.append_output(f"Command: {' '.join(cmd)}\n{output}")
    
    def set_monitor(self):
        self.append_output(f"\n=== Setting MONITOR mode on {self.interface} ===")
        commands = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "type", "monitor"],
            ["ip", "link", "set", self.interface, "up"]
        ]
        
        for cmd in commands:
            output = self.run_command(cmd)
            self.append_output(f"Command: {' '.join(cmd)}\n{output}")
    
    def set_txpower(self):
        self.append_output(f"\n=== Setting TX power to 30 dBm on {self.interface} ===")
        
        # Set regulatory domain
        self.append_output("Setting regulatory domain to US...")
        self.run_command("iw reg set US", shell=True)
        self.run_command("rfkill unblock all", shell=True)
        
        # Set TX power
        commands = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "txpower", "fixed", "3000"],
            ["ip", "link", "set", self.interface, "up"]
        ]
        
        for cmd in commands:
            output = self.run_command(cmd)
            self.append_output(f"Command: {' '.join(cmd)}\n{output}")
    
    def change_mac(self):
        self.append_output(f"\n=== Changing MAC address on {self.interface} ===")
        commands = [
            ["ip", "link", "set", self.interface, "down"],
            ["macchanger", "-r", self.interface],
            ["ip", "link", "set", self.interface, "up"]
        ]
        
        for cmd in commands:
            output = self.run_command(cmd)
            self.append_output(f"Command: {' '.join(cmd)}\n{output}")
    
    def show_settings(self):
        self.append_output(f"\n=== Current Settings for {self.interface} ===")
        commands = [
            ["iw", "dev", self.interface, "info"],
            ["iw", "reg", "get"]
        ]
        
        for cmd in commands:
            output = self.run_command(cmd)
            self.append_output(f"Command: {' '.join(cmd)}\n{output}")
            
        # Show MAC address using file read instead of cat command
        try:
            with open(f"/sys/class/net/{self.interface}/address", "r") as f:
                mac_addr = f.read().strip()
            self.append_output(f"MAC Address: {mac_addr}")
        except Exception as e:
            self.append_output(f"Error reading MAC address: {str(e)}")
    
    def scan_networks(self):
        if self.scan_running or self.wash_running:
            self.append_output("Another scan is already running!")
            return
            
        self.append_output(f"\n=== Scanning networks on {self.interface} (airodump-ng) ===")
        self.append_output("Press Stop button to terminate scanning")
        
        # Show stop button
        self.stop_scan_btn.show()
        self.scan_running = True
        
        def run_scan():
            try:
                self.scan_process = subprocess.Popen(
                    ["airodump-ng", self.interface, "--output-format", "csv"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    preexec_fn=os.setsid  # Create new process group
                )
                
                # Read output line by line
                while self.scan_running:
                    line = self.scan_process.stdout.readline()
                    if not line:
                        break
                    self.output_signal.output_signal.emit(line.strip())
                
                # Clean up
                if self.scan_process and self.scan_running:
                    try:
                        # Kill the entire process group
                        os.killpg(os.getpgid(self.scan_process.pid), signal.SIGTERM)
                        self.scan_process.wait(timeout=2)
                    except:
                        try:
                            os.killpg(os.getpgid(self.scan_process.pid), signal.SIGKILL)
                        except:
                            pass
                
                # When process ends, hide stop button
                self.output_signal.output_signal.emit("\nScan completed.")
                self.scan_running = False
                self.stop_scan_btn.hide()
                
            except Exception as e:
                self.output_signal.output_signal.emit(f"Error: {str(e)}")
                self.scan_running = False
                self.stop_scan_btn.hide()
        
        # Run in separate thread
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def test_wash(self):
        if self.wash_running or self.scan_running:
            self.append_output("Another scan is already running!")
            return
            
        self.append_output(f"\n=== Testing WPS networks on {self.interface} ===")
        self.append_output("Press Stop WPS Scan button to terminate")
        
        # Show stop button
        self.stop_wash_btn.show()
        self.wash_running = True
        
        def run_wash():
            try:
                self.wash_process = subprocess.Popen(
                    ["wash", "-i", self.interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    preexec_fn=os.setsid  # Create new process group
                )
                
                # Read output line by line
                while self.wash_running:
                    line = self.wash_process.stdout.readline()
                    if not line:
                        break
                    self.output_signal.output_signal.emit(line.strip())
                
                # Clean up
                if self.wash_process and self.wash_running:
                    try:
                        # Kill the entire process group
                        os.killpg(os.getpgid(self.wash_process.pid), signal.SIGTERM)
                        self.wash_process.wait(timeout=2)
                    except:
                        try:
                            os.killpg(os.getpgid(self.wash_process.pid), signal.SIGKILL)
                        except:
                            pass
                
                # When process ends, hide stop button
                self.output_signal.output_signal.emit("\nWPS scan completed.")
                self.wash_running = False
                self.stop_wash_btn.hide()
                
            except Exception as e:
                self.output_signal.output_signal.emit(f"Error: {str(e)}")
                self.wash_running = False
                self.stop_wash_btn.hide()
        
        # Run in separate thread
        self.wash_thread = threading.Thread(target=run_wash)
        self.wash_thread.daemon = True
        self.wash_thread.start()
    
    def stop_scan(self):
        """Stop the currently running scan"""
        try:
            self.scan_running = False
            if self.scan_process:
                try:
                    # Kill the entire process group
                    os.killpg(os.getpgid(self.scan_process.pid), signal.SIGTERM)
                    self.scan_process.wait(timeout=2)
                except:
                    try:
                        os.killpg(os.getpgid(self.scan_process.pid), signal.SIGKILL)
                    except:
                        pass
                self.scan_process = None
            self.append_output("\nNetwork scan stopped by user")
            self.stop_scan_btn.hide()
        except Exception as e:
            self.append_output(f"Error stopping scan: {str(e)}")
            self.stop_scan_btn.hide()
    
    def stop_wash(self):
        """Stop the currently running WPS scan"""
        try:
            self.wash_running = False
            if self.wash_process:
                try:
                    # Kill the entire process group
                    os.killpg(os.getpgid(self.wash_process.pid), signal.SIGTERM)
                    self.wash_process.wait(timeout=2)
                except:
                    try:
                        os.killpg(os.getpgid(self.wash_process.pid), signal.SIGKILL)
                    except:
                        pass
                self.wash_process = None
            self.append_output("\nWPS scan stopped by user")
            self.stop_wash_btn.hide()
        except Exception as e:
            self.append_output(f"Error stopping WPS scan: {str(e)}")
            self.stop_wash_btn.hide()
    
    def test_injection(self):
        self.append_output(f"\n=== Testing packet injection on {self.interface} ===")
        # Use shorter timeout and run in thread to prevent hanging
        def run_injection():
            output = self.run_command(["aireplay-ng", "-9", self.interface], timeout=10)
            self.output_signal.output_signal.emit(output)
        
        thread = threading.Thread(target=run_injection)
        thread.daemon = True
        thread.start()
    
    def restart_networkmanager(self):
        self.append_output("\n=== Restarting NetworkManager ===")
        output = self.run_command(["systemctl", "restart", "NetworkManager"])
        self.append_output(output)
    
    def clear_output(self):
        self.output_console.clear()

def main():
    # Check if running as root
    if os.geteuid() != 0:
        QMessageBox.critical(None, "Error", "This application must be run as root!")
        return
    
    app = QApplication(sys.argv)
    window = WiFiToolGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
