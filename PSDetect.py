from scapy.all import *
import threading

"""
Program listens to incoming packets and detects if
a port scan occurs on the device
usage: sudo python3 PSDetect.py
@author Mason Horne
@version 11/15/21
"""

# List of all current connections being made with device
connections = {}


def clear(ip):
    """
    Clears the tuple for the provided ip in the connections list
    :param ip: ip to clear data for
    :return: None
    """
    # In case the connection has already been cleared
    if connections[ip] is not None:
        connections[ip][3].cancel()
        connections[ip] = None


def inspect_packet(p):
    """
    Gathers the packets IP and updates its value in
    the connections list based on its past connections
    :param p: packet being inspected
    :return: None
    """
    # Only process incoming packets not responses
    # Gather packet ip
    ip = p[IP].src
    # Check if currently contains an entry for packet
    if connections.get(ip) is None:
        # Store the port this ip last connected to and initialize count
        timer = threading.Timer(5.0, clear, [ip])
        timer.start()
        connections[ip] = (1, 1, p.dport, timer)
    else:
        # Otherwise check if consecutive port was hit
        if connections[ip][2] == p.dport:
            return
        # Check if ports are incrementing
        if connections[ip][2] == p.dport - 1 and connections[ip][1] == 1:
            connections[ip] = (connections[ip][0] + 1, connections[ip][1], p.dport, connections[ip][3])
            # If over 15 then alert of scan and reset counter
            if connections[ip][0] > 14:
                print('Scanner detected. The scanner originated from host %s.' % ip)
                connections[ip][3].cancel()
                connections[ip] = None
                return
        # Check if ports are decrementing
        elif connections[ip][2] == p.dport + 1 and connections[ip][0] == 1:
            connections[ip] = (connections[ip][0], connections[ip][1] + 1, p.dport, connections[ip][3])
            # If over 15 then alert of scan and reset counter
            if connections[ip][1] > 14:
                print('Scanner detected. The scanner originated from host %s.' % ip)
                connections[ip][3].cancel()
                connections[ip] = None
                return
        # If not reset count to 1 for most recent port
        else:
            connections[ip][3].cancel()
            connections[ip] = None
            timer = threading.Timer(5, clear, [ip])
            timer.start()
            connections[ip] = (1, 1, p.dport, timer)
        # Update last port for ip to this new port


# Start listening filtering only incoming TCP requests ACK = 0 w/ IP Layer
sniff(prn=inspect_packet, lfilter=lambda x: x.haslayer(TCP) and hasattr(x, 'ack') and x.ack == 0 and x.haslayer(IP))
# In order to test locally use iface = lo
#sniff(iface="lo", prn=inspect_packet, lfilter=lambda x: x.haslayer(TCP) and hasattr(x, 'ack') and x.ack == 0 and x.haslayer(IP))