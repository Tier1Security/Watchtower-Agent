
![watchtower-horizontal](https://github.com/user-attachments/assets/b8b6995d-6ceb-40ce-a3a9-1edd8b6ae4ea)


This is the agent that handles all security related events as well as blocking of IP's that try to brute force into Windows machines. This is part of an Watchtower SIEM/IPS solution made by Tier 1 Security. It uses less than 25MB of ram and less than 1% of CPU during runtime. 

You are free to run the script by itself without a license. 

## Features
1. Pushes security events to the cloud (will add the demo server for this soon)
2. Blocks IP addresses by adding them to the windows firewall. This feature is working and has been tested on both Windows 10 and Windows 11 machines. 

## Installation - Local

1. You don't need a key for the program to work locally, only if you want to use the cloud based dashboard.
  
2. The local server is in development.
   
3. You can also use whatever log ingestion platform you would like.

## Installation - Cloud

1. After buying a license from the dashboard you will be given a key. 

2. Add this key to the Watchtower Agent Script as shown below in line 45.

```csharp
private const string license = "<LICENSE>";
```

3. Run the program as an Administrator because it needs to access Windows Security Events in real time and this needs elevated priveleges. 

4. You should see this output from the script every time a log has been sent to your dashboard successfully. 

CMD output of a successful POST request:
```batchfile
POST request successful!

```

## How it Works - Security Event Ingestion

1. The program needs to run as admin as it needs elevated privileges to listen for security events.
2. There is a .NET library called "Systems.Collections" that allows you to programmatically listen for new security events.
3. This is different from querying historical logs every x unit of time as the event's can be subscribed to in real time.
4. When a security event happens on the machine, the script will send out a POST request to a server and the server will send back if the request is successful or not.

## How it Works - Brute Force Prevention

1. The program watches for repeated password attempts, specifically Windows Event 4625 (Failed Authentication)
2. If an IP address tries too many times (passes the threshold) then the program will add that IP address to Windows Firewall as a blocked IP.
3. The program can also send this information to the Tier 1 Dashboard. 

## Usage

Important: must be run with Administrator privileges as reading Security Event Logs from Windows needs elevated privileges. 

If you don't specify where to send the data, the script will still run. It just won't send any security related data anywhere. It will still block IP addresses that try to brute force into machines. 


## Future
We are in the process of converting this script into a daemon so that it can in the background as a Windows service. The implementation will resemble CLI applications where the user can start/stop/ query the status of the program all through CMD or Powershell like the popular DNS sinkhole PiHole: https://pi-hole.net/

