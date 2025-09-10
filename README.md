# I wrote this program for my RTL88au ( awus036ach ) wifi card to simplify the whole shit.
It is written in python, with all needed possibilities for your RTL8812AU : monitor / managed mode, txpower, testing etc.

INSTALLATION ( only tested on linux kali ( 6.12.38+kali-amd64 ) :
# Install only the essential dependencies
sudo apt update
sudo apt install python3-pyqt5

# Save the script
nano wifi_tool_gui.py

# Make executable and run
chmod +x wifi_tool_gui.py
sudo ./wifi_tool_gui.py
