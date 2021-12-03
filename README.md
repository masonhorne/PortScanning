# Port Scanning #

#### A collection of python files containing implementations of a Port Scanner. ####

- **PortScan<span>.py** : Contains a basic implementation of a Port Scanner
    - `python3 PortScan.py <IP TO SCAN>` 
- **PSDetect<span>.py** : Contains a Port Scan Detector that alerts when 15 consecutive ports are hit within 5 seconds
    - `sudo python3 PSDetect.py`
- **PortScanToo<span>.py** : Contains another Port Scanner that scans even then odd ports in blocks of 256.
    - `python3 PortScanToo.py <IP TO SCAN>`

    
**DISCLAIMER**
>Port Scanning can be seen as, or construed as a crime. You should never execute a port scanner against any website or IP address without the explicit, written permission from the owner of the server or computer you are targeting. Port scanning can be used as a security tool for assesing vulnerabilities within a system. Thus, if you have no good reason to be testing these things, it can be assumed you are attacking the system.


