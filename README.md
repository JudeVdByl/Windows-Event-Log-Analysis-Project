# Windows Event Log Analysis Project

This project showcases my expertise in utilizing Windows Event Logs for forensic analysis, threat detection, and system monitoring. Each scenario involves analyzing logs using specific Event IDs, timestamps, and tools like PowerShell to detect suspicious activities and confirm findings. The attached images provide evidence and illustrate the methodologies employed.

---

## Objective

To demonstrate proficiency in analyzing Windows Event Logs to uncover security incidents, investigate anomalies, and document findings using PowerShell and other Windows-native tools.

---

## Skills Demonstrated

- Advanced Windows Event Log analysis.
- Expertise in PowerShell for querying and filtering event data.
- Incident detection and response using forensic methodologies.
- Understanding of key Event IDs for specific use cases.

---

## Tools Used

- **PowerShell**: To extract, filter, and analyze event logs programmatically.
- **Event Viewer**: To navigate and validate event data.
- **Windows Security Logs**: To track and confirm system activities.
- **Scripting Techniques**: To automate log querying and analysis.

---

## Scenarios

### **Scenario 1: Identifying the Second PowerShell Command**

**Objective**: Filter on `Event ID 4104` and determine the second command executed in the session.  
- **Event ID**: `4104`
- **Command**: `whoami`

![Filter on Event ID 4104](https://github.com/user-attachments/assets/2820c130-8443-49cf-b708-3c0405c2fe01)


**Analysis**: Using PowerShell to locate the second logged command, the data revealed that the `whoami` command was executed. The attached image shows the query results from Event Viewer.

---

### **Scenario 2: Understanding Task Categories for PowerShell Commands**

**Objective**: Analyze `Event ID 4104` for task categories.  
- **Task Category**: `Execute a Remote Command`

![Task Category for Event ID 4104]![image](https://github.com/user-attachments/assets/d9c46f14-4a08-4ce7-9757-980085df4c1f)


**Analysis**: This scenario involved identifying the task category associated with a PowerShell session. The image demonstrates how verbose logging highlights the specific category.

---

### **Scenario 3: Counting Log Names on the Machine**

**Objective**: Count the number of logs available on the system.  
- **Command Used**: `wevtutil el | Measure-Object`
- **Result**: `1071`

![Log Count Using PowerShell]![image](https://github.com/user-attachments/assets/9e2bf8a4-0cf6-4e3f-bbc0-ad6f07e89ee1)


**Analysis**: Using PowerShell, I determined that the machine contains 1,071 logs. This count provides an understanding of the breadth of available logging on the system.

---

### **Scenario 4: Querying OpenSSH Logs**

**Objective**: Identify log names related to OpenSSH.  
- **Log Names**: `OpenSSH/Admin`, `OpenSSH/Operational`

![OpenSSH Logs]![image](https://github.com/user-attachments/assets/b68f97f6-505e-427a-a74b-3f53f73d1985)


**Analysis**: Using the PowerShell command, I extracted log names associated with OpenSSH services for further analysis.

---

### **Scenario 5: PowerShell Downgrade Attack Detection**

**Objective**: Detect PowerShell downgrade attacks using Event ID `400`.  
- **Event ID**: `400`
- **Date and Time**: `12/18/2020 7:50:33 AM`

![PowerShell Downgrade Attack]![image](https://github.com/user-attachments/assets/1d0f7ade-1e79-4899-8c91-da6da542a6a3)


**Analysis**: This scenario demonstrates identifying downgrade attacks by monitoring specific Event IDs. The attached image shows the log query and its results.

---

### **Scenario 6: Monitoring Log Clearing Activity**

**Objective**: Track log clearing events using Event ID `104`.  
- **Event Record ID**: `27736`

![Log Clearing Event]![image](https://github.com/user-attachments/assets/2be27d76-3d28-4ac5-a546-963ea838e82a)


**Analysis**: By monitoring the `Log clear` event, I ensured visibility into log tampering activities, as shown in the image.

---

### **Scenario 7: Emotet Malware Investigation**

**Objective**: Detect suspicious PowerShell activity related to Emotet malware.  
- **Event ID**: `4104`
- **First Variable**: `$Va5w3n8`
- **Date and Time**: `8/25/2020 10:09:28 PM`
- **Process ID**: `6620`

![Emotet Malware Analysis]![image](https://github.com/user-attachments/assets/2b32ef6d-b019-4388-82e1-55f8ddfaffb4)![image](https://github.com/user-attachments/assets/65fbb1e3-05da-4a31-827b-e04e3e084b23)



**Analysis**: The image illustrates how PowerShell logs were analyzed to uncover encoded payloads and malicious activities, revealing Emotet-related events.

---

### **Scenario 8: Investigating Group Enumeration Activity**

**Objective**: Confirm group enumeration activities by identifying the Security ID and Event ID.  
- **Group Security ID**: `S-1-5-32-544`
- **Event ID**: `4799`

![Group Enumeration Analysis]![image](https://github.com/user-attachments/assets/c01da7c9-cd1b-4156-897b-6b8524b8a035)


**Analysis**: This scenario involved investigating unusual activity on the system. By searching logs for specific group-related actions, I confirmed enumeration attempts, as shown in the attached image.

---

## Key Commands

Here are some of the critical commands used in this project:

```powershell
# Count all log names on the system
wevtutil el | Measure-Object

# Query logs related to OpenSSH
Get-WinEvent -ListLog * | Where-Object { $_.LogName -match "OpenSSH" }

# Detect PowerShell downgrade attacks
Get-WinEvent -Path .\Desktop\merged.evtx -FilterXPath '*[System/EventID=400]' -MaxEvents 10

# Monitor log clearing events
Get-WinEvent -Path .\Desktop\merged.evtx -FilterXPath '*[System/EventID=104]' -MaxEvents 10 | Select-Object RecordId

# Investigate suspicious PowerShell activity
Get-WinEvent -Path .\Desktop\merged.evtx -FilterXPath '*[System[EventID=4104]]' -MaxEvents 1 | Select-Object -Property Id, ProcessId, TimeCreated, Message

# Search group enumeration logs
Get-WinEvent -Path .\Desktop\merged.evtx | Where-Object { $_.Message -match "S-1-5-32-544" } | Select-Object TimeCreated, Id, Message
