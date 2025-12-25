# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/AntonisVos/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---


## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "antonislab" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at 2025-12-25T20:11:56.6320899Z.


**Query used to locate events:**

DeviceFileEvents  
| where DeviceName == "antonis-mde"  
| where InitiatingProcessAccountName == "antonislab"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


<img width="1075" height="634" alt="Screenshot 2025-12-25 at 3 24 12 PM" src="https://github.com/user-attachments/assets/54eb7eba-02ac-4c38-93f1-7e5f640ef0bc" />

---


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.3 (1)". Based on the logs returned, on Dec 25, 2025 at 02:58:36 PM, an employee on the "Antonis-MDE" device ran the file `tor-browser-windows-x86_64-portable-15.0.3 (1)` from their Downloads folder, using a command that triggered a silent installation.


**Query used to locate event:**


DeviceProcessEvents  
| where DeviceName == "antonis-mde"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3 (1)"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine


<img width="900" height="432" alt="Screenshot 2025-12-25 at 3 32 53 PM" src="https://github.com/user-attachments/assets/ea53a85d-b16b-4232-97ff-cdb1c503b2a2" />

---


### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "antonislab" actually opened the TOR browser. There was evidence that they did open it on Dec 25, 2025 at 02:59:25 PM. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

DeviceProcessEvents  
| where DeviceName == "antonis-mde"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc


<img width="902" height="629" alt="Screenshot 2025-12-25 at 3 34 55 PM" src="https://github.com/user-attachments/assets/371d66c9-d38f-4bc4-afec-3d0b4525b74f" />

---


### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On Dec 25, 2025 at 03:09:45 PM, an employee on the "Antonis-MDE" device successfully established a connection to the remote IP address 37.143.117.173 on port `9050`. The connection was initiated by the process `tor.exe`, located in the folder  'c:\users\antonislab\desktop\torbrowser\browser\torbrowser\tor\tor.exe' . There were a few other connections to sites over port `443` and `9150` as well.


**Query used to locate events:**

DeviceNetworkEvents  
| where DeviceName == "antonis-mde"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath 
| order by Timestamp desc


<img width="883" height="519" alt="Screenshot 2025-12-25 at 3 40 29 PM" src="https://github.com/user-attachments/assets/ba0dc4c7-2498-4d3e-b180-9f139c9452aa" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-12-25T19:41:14.6824858Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.3 (1)` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\antonislab\Downloads\tor-browser-windows-x86_64-portable-15.0.3 (1).exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-12-25T19:58:36.2345497Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.3 (1).exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3 (1).exe /S`
- **File Path:** `C:\Users\antonislab\Downloads\tor-browser-windows-x86_64-portable-15.0.3 (1)`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-12-25T19:59:25.225697Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\antonislab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-12-25T20:01:49.5683637Z`
- **Event:** A network connection to IP `37.143.117.173` on port `9050` by user "antonislab" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\antonislab\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-12-25T20:01:23.4201337Z` - Connected to `185.73.220.8` on port `443`.
  - `2025-12-25T20:01:16.7025959Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-14T16:15:22.6128464Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\antonislab\Desktop\tor-shopping-list.txt`

---

## Summary

The user "antonislab" on the "Antonis-MDE" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Antonis-MDE` by the user `antonislab`. The device was isolated, and the user's direct manager was notified.

---
