# Registry Run Key Persistence

## Description

Detects creation or editing of keys that run on startup in the Windows Registry. These locations are commonly targeted in order to establish
persistence after system reboots.

Listed in Sysmon as event ID 13: RegistryEvent (Value Set)

From the extracted XML, the current detection makes use of:
| Field | Purpose |
| :---|:---|
|EventID|Confirms event ID 13|
|SystemTime|Timestamp of modification|
|Image|Executable making the registry change|
|TargetObject|The path to the changed registry|
|Details|Data written into the registry value|
|User|Account resposible for the change|

## Detection Logic

1. Parse Sysmon event ID 13
2. Extract TargetObject
3. Compare TargetObject to known run paths
4. If matched:
   1. Extract time stamp
   2. Extract process image
   3. Extract registry change
   4. Extract user
   5. Generate and append alert to list

## Potential False Positives
- Windows updates
- Legitimate software installers
- Legitimate application updaters
- IT Administration tools
- Task manager startup changes

## Raw XML Data

Example XML from [Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)
```text
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>13</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>13</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-05-11T04:31:19.619361100Z" />
    <EventRecordID>725973</EventRecordID>
    <Correlation />
    <Execution ProcessID="3188" ThreadID="3836" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>rfsH.lab.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="EventType">SetValue</Data>
    <Data Name="UtcTime">2017-05-11 04:31:19.613</Data>
    <Data Name="ProcessGuid">{A23EAE89-E8BF-5913-0000-0010DB9F7109}</Data>
    <Data Name="ProcessId">25228</Data>
    <Data Name="Image">C:\Windows\regedit.exe</Data>
    <Data Name="TargetObject">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\BadWolf</Data>
    <Data Name="Details">run</Data>
  </EventData>
</Event>
```
