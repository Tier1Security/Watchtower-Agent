![logo-bw](https://github.com/user-attachments/assets/43246189-f1b3-4f8f-bd44-bf07a457347f)

# Watchtower - Agent
This is the agent that handles all security related events as well as blocking of IP's that try to brute force into Windows machines. This is part of an Watchtower SIEM/IPS solution made by Tier 1 Security. It uses less than 25MB of ram and less than 1% of CPU during runtime. 

## Features
1. Pushes security events to the cloud (will add the demo server for this soon)
2. Blocks IP addresses by adding them to the windows firewall. This feature is working and has been tested on both Windows 10 and Windows 11 machines. 

## Installation
For the time being, please use either an IDE of your choosing and import the existing dotnet solution. Either that or you can download the run the executable directly.

## Usage

Important: must be run with Administrator privileges as reading Security Event Logs from Windows needs elevated privileges. 

If you don't specify where to send the data, the script will still run. It just won't send any security related data anywhere. It will still block IP addresses that try to brute force into machines. 

CMD output of a successful POST request:
```batchfile
POST request successful!

```
## Future
We are in the process of converting this script into a daemon so that it can in the background as a Windows service. The implementation will resemble CLI applications where the user can start/stop/ query the status of the program all through CMD or Powershell like the popular DNS sinkhole PiHole: https://pi-hole.net/

