import sys
import socket
import time

"""
Program that scans the ports of a provided host while avoiding detection
usage: python3 PortScanToo.py <host name>
@author Mason Horne
@version 11/15/21
"""


def scan_port(p):
    """
    Simple function that returns boolean telling if
    the supplied port is open on the ip being probed
    :param p: port to check connection on
    :return: True if port is open and false otherwise
    """
    # If outside of port range return false
    if p > 65535 or p < 0: return False
    # Create socket for IPv4 and TCP (AF_INET and SOCK_STREAM respectively)
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Check if can connect to target ip on given port
    res = scanner.connect_ex((ip, p))
    # Close the scanner and return whether connection was successful
    scanner.close()
    return True if res == 0 else False


# Read in the ip to scan ports for
ip = socket.gethostbyname(sys.argv[1])
# Variables to keep up with open port count and port numbers
open_ports = []
# Begin scanning target ip
print("Scanning %s" % sys.argv[1])
print("-------------------------")
# Outputs the port number and the visual for each block of ports
# where ports are blocked into sections of 2^12 (4096)
start = time.time()
for section in range(16):  # NOTE 65535 / 4096 is 16 total lines to output
    print("%5d" % (section * 4096), end='  ')
    # Outputs a . for every 256 ports scanned and outputs an !
    # after the . if a port is open within that range of 256
    for i in range(17):  # NOTE 4096 / 256 is 16 total sections for outputing
        print('.', end='')
        # Check all even numbered ports
        for ii in range(0, 256, 2):
            if scan_port((section * 4096) + (i * 256) + ii):
                open_ports.append((section * 4096) + (i * 256) + ii)
                print('!', end='')
        # Check all odd numbered ports
        for ii in range(1, 256, 2):
            if scan_port((section * 4096) + (i * 256) + ii):
                open_ports.append((section * 4096) + (i * 256) + ii)
                print('!', end='')
    print()  # Move to next block of ports to output
# Calculate the total time for the scan to complete
elapsed = time.time() - start
# Output summary of scan statistics
print("Scan finished!")
print("-------------------------")
print("%10d ports found" % len(open_ports))
print("%10.2f seconds elapsed" % elapsed)
print("%10.2f ports per second" % (65535 / elapsed))
print("Open ports:")
print("-------------------------")
# When outputting ports if no service name is defined
# output [unassigned] in place of the service name
for port in open_ports:
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "[unassigned]"
    print("%5d: %s" % (port, service))
print("\nTerminating normally")