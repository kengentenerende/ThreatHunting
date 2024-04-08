# THP Cheat Sheet ELK and Splunk
# Splunk
Splunk is one of the leading SIEM solutions in the market that provides the ability to collect, analyze and correlate the network and machine logs in real-time.  Splunk can be used for Application Management, Operations Management, Security & Compliance, etc.

# SPLUNK - Visualization

|     Fields             |     Descripition.    |
|------------------------------------|------------------------------------|
|     1- Selected Fields             |     Splunk extracts   the default fields like source, sourcetype, and host, which appear in each   event, and places them under the selected fields column. We can select other   fields that seem essential and add them to the list.    |
|     2- Interesting Fields          |     Pulls   all the interesting fields it finds and displays them in the left panel to   further explore.                                                                                                                                 |
|     3- Alpha-numeric fields 'α'    |     This   alpha symbol shows that the field contains text values.                                                                                                                                                                        |
|     4- Numeric fields '#'          |     This   symbol shows that this field contains numerical values.                                                                                                                                                                        |
|     5- Count                       |     The   number against each field shows the number of events captured in that   timeframe.                                                                                                                                              |

## Search Field Operators
|     Field Name                  |     Operator    |     Example                        |     Explanation                                                                                                                                                                 |
|---------------------------------|-----------------|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Equal                       |    `=`          |     UserName=Mark                  |     This   operator is used to match values against the field. In this example, it will   look for all the events, where the value of the field UserName is equal to   Mark.    |
|     Not Equal to                |    `!=`         |     UserName!=Mark                 |     This   operator returns all the events where the UserName value does not match Mark.                                                                                        |
|     Less than                   |    `<`          |     Age   < 10                     |     Showing   all the events with the value of Age less than 10.                                                                                                                |
|     Less than or Equal to       |    `<=`         |     Age   <= 10                    |     Showing   all the events with the value of Age less than or equal to 10.                                                                                                    |
|     Greater than                |    `> `         |     Outbound_traffic   > 50 MB     |     This   will return all the events where the Outbound traffic value is over 50 MB.                                                                                           |
|     Greater Than or Equal to    |    `>=`         |     Outbound_traffic   >= 50 MB    |     This   will return all the events where the Outbound traffic value is greater or   equal to 50 MB.                                                                          |

## Boolean Operators
|     Operator    |     Syntax                               |     Explanation                                                                              |
|-----------------|------------------------------------------|----------------------------------------------------------------------------------------------|
|     `NOT`         |     field_A NOT value                    |     Ignore   the events from the result where field_A contain the specified value.           |
|     `OR`         |     field_A=value1 OR field_A=value2     |     Return   all the events in which field_A contains either value1 or value2.               |
|     `AND`         |     field_A=value1 AND field_B=value2    |     Return   all the events in which field_A contains value1 and field_B contains value2.    |

## Wild Card
|     Wildcard symbol    |     Example               |     Explanation                                                                               |
|------------------------|---------------------------|-----------------------------------------------------------------------------------------------|
|     `*`                  |           status=fail*    |     It   will return all the results with values like     status=failed     status=failure    |

##  Filtering in SPL - Rex

|     Command        |     rex                                                                                                                                                                                                                           |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Explanation    |     Rex command matches the value of the specified field against the unanchored regular expression and extracts the named groups into fields of the corresponding names.    |
|     Syntax         |     `\| rex  [field=<field>] <regex-expression>`                                                                                                                                                                                       |
|     Example        |     `\| rex field=form_data "passwd=(?<passwd>[^&]+)" `  

##  Filtering in SPL - Fields

|     Command        |     fields                                                                                                                                                                                                                           |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Explanation    |     Fields   command is used to add or remove mentioned fields from the search results. To   remove the field, minus sign ( - ) is used before the fieldname and plus ( +   ) is used before the fields which we want to display.    |
|     Syntax         |     `\| fields <field_name1>  <field_name2>`                                                                                                                                                                                       |
|     Example        |     `\| fields +   HostName - EventID `                                                                                                                                                                                              |

##  Filtering in SPL - Search
|     Command        |     search                                                                                                     |
|--------------------|----------------------------------------------------------------------------------------------------------------|
|     Explanation    |     This command is used to search for the raw text while   using the chaining command \|                      |
|     Syntax         |     `\| search  <search_keyword>`                                                                            |
|     Example        |     `\| search   "Powershell" `                                                                                |

##  Filtering in SPL - Dedup
|     Command        |     dedup                                                                                                                                                                                                                         |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Explanation    |     Dedup   is the command used to remove duplicate fields from the search results. We   often get the results with various fields getting the same results. These   commands remove the duplicates to show the unique values.    |
|     Syntax         |     `\| dedup <fieldname>`                                                                                                                                                                                                      |
|     Example        |     `\| dedup EventID`                                                                                                                                                                                                            |

##  Structuring in SPL - Table
|     Explanation    |     `Each   event has multiple fields, and not every field is important to display. The   Table command allows us to create a table with selective fields as columns.   |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Syntax         |     `\| table <field_name1> <fieldname_2>`                                                                                                                            |
|     Example        |     `\| table     \| head 20` # will return the top 20 events from the result   list.                                                                                   |

##  Structuring in SPL - Head
|     Explanation    |     `The head command returns the first 10 events   if no number is specified.                                                                   |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
|     Syntax         |     `\| head <number>`                                                                                                                         |
|     Example        |     `\| head`   # will return the top 10 events from the   result list     \| head 20    # will return the top 20 events from   the result list  |

##  Structuring in SPL - Tail
|     Explanation    |     `The Tail command returns the last 10   events if no number is specified.                                                                   |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
|     Syntax         |     `\| tail <number>`                                                                                                                        |
|     Example        |     `\| tail` # will return the last 10 events from the result   list     \| tail 20   # will return the last 20 events from the   result list  |

##  Structuring in SPL - Sort
|     Explanation    |     `The Sort command allows us to order   the fields in ascending or descending order.   |
|--------------------|-------------------------------------------------------------------------------------------|
|     Syntax         |     `\| sort <field_name>`                                                                |
|     Example        |     `\| sort Hostname # This will sort the result in Ascending order.`                    |

##  Structuring in SPL - Reverse
| Explanation | The `reverse` command simply reverses the order of the events. |
|-------------|--------------------------------------------------------------|
| Syntax      | `\| reverse`                                                  |
| Example     | `<Search Query> \| reverse`                                  |

## Structuring in SPL - Transaction
|     Command        |     transaction                                                              |
|--------------------|----------------------------------------------------------------------|
|     Explanation    |     This   commands groups search results into transactions.         |
|     Syntax         |     `\|   transaction  <field_name>     \|   transaction <field_name> maxspan=5s maxpause=30s <field_name>`       |
|     Example        |     `transaction clientip maxspan=5s maxpause=30s \| table host`                                          |

## Transformational in SPL - Top
|     Command        |     top                                                              |
|--------------------|----------------------------------------------------------------------|
|     Explanation    |     This   command returns frequent values for the top 10 events.    |
|     Syntax         |     `\|   top  <field_name>     \|   top limit=6 <field_name>`       |
|     Example        |     `top   limit=3 EventID`                                          |

## Transformational in SPL - Rare
|     Command        |     rare                                                                                                               |
|--------------------|------------------------------------------------------------------------------------------------------------------------|
|     Explanation    |     This   command does the opposite of top command as it returns the least frequent   values or bottom 10 results.    |
|     Syntax         |     `\|   rare <field_name>     \|   rare limit=6 <field_name>`                                                          |
|     Example        |     `rare   limit=3 EventID`                                                                                             |

## Transformational in SPL - Highlight

|     Command        |     highlight                                                                                  |
|--------------------|------------------------------------------------------------------------------------------------|
|     Explanation    |     The   highlight command shows the results in raw events mode with fields   highlighted.    |
|     Syntax         |     `highlight        <field_name1>      <field_name2>`                                          |
|     Example        |     `highlight   User, host, EventID, Image`                                                     |

## Transformational in SPL - Stats
|     Command    |     Explanation                                                            |     Syntax                                 |     Example                       |
|----------------|----------------------------------------------------------------------------|--------------------------------------------|-----------------------------------|
|     Average    |     This   command is used to calculate the average of the given field.    |     `stats   avg(field_name)`                |     `stats   avg(product_price)`|
|     Max        |     It   will return the maximum value from the specific field.            |     `stats   max(field_name)`                |     `stats   max(user_age)`     |
|     Min        |     It   will return the minimum value from the specific field.            |     `stats   min(field_name)`                |     `stats   min(product_price)`|
|     Sum        |     It   will return the sum of the fields in a specific value.            |     `stats   sum(field_name)`                |     `stats   sum(product_cost)` |
|     Count      |     The   count command returns the number of data occurrences.            |     `stats   count(function) AS new_NAME`    |     `stats   count(source_IP)`  |


## Transformational in SPL - Chart

|     Command        |     chart                                                                               |
|--------------------|-----------------------------------------------------------------------------------------|
|     Explanation    |     The   chart command is used to transform the data into tables or visualizations.    |
|     Syntax         |     `\|   chart <function>`                                                               |
|     Example        |     `\| chart count by   User`                                                            |

## Transformational in SPL - Timechart
|     Command        |     timechart                                                                                                                                           |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
|     Explanation    |     The   timechart command returns the time series chart covering the field following   the function mentioned. Often combined with STATS commands.    |
|     Syntax         |     `\|   timechart function  <field_name>`                                                                                                               |
|     Example        |     `\| timechart count   by Image`                                                                                                                       |

# SPLUNK - Intel-driven Threat Hunting
- [Splunk Boss of the SOC: Hunting an APT with Splunk & MITRE ATT&CK Framework (Part 1)](https://medium.com/@shunxianou/splunk-boss-of-the-soc-hunting-an-apt-with-splunk-mitre-att-ck-framework-part-1-b6d3553b788e)
- [Splunk Boss of the SOC: Hunting an APT with Splunk & MITRE ATT&CK Framework (Part 2)](https://medium.com/@shunxianou/splunk-boss-of-the-soc-hunting-an-apt-with-splunk-mitre-att-ck-framework-part-2-5851a996f647)
- [Threat Hunting on Splunk Beginner Cheat Sheet — Mastering Sourcetypes & Fields of Interest](https://medium.com/@shunxianou/threat-hunting-on-splunk-beginner-cheat-sheet-mastering-sourcetypes-fields-of-interest-3dee5541b901)
- [TryHackMe-BP-Splunk/Advanced-Persitent-Threat](https://www.aldeid.com/wiki/TryHackMe-BP-Splunk/Advanced-Persitent-Threat)
- [Splunk.BOTS / Boss of the SOC Ver.1 Write-Up (30/30)](https://www.absolroot.com/ed93f920-3da1-4607-b990-6fce9fef5be1)
- [TryHackMe-BP-Splunk](https://www.aldeid.com/wiki/TryHackMe-BP-Splunk)

**Available Indexes and Their Counts**

- This search command counts the number of events for each index. This preliminary search helps you understand the volume of data in each index and provides a broad view of your environment. 
```
| tstats count WHERE index=* by index
```
**Available Sourcetypes and Their Counts — Metadata Command**
```
|metadata type=sourcetypes index=botsv2
|eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
|eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
|eval recentTime=strftime(recentTime, "%Y-%m-%d %H:%M:%S")
|sort -totalCount
```

## Data Sourcetypes
`Windows-TA`
- This is the default Windows-TA for Splunk and collects not only EventLog data but also registry information

`Sysmon-TA`
- This TA collects information generated from the Sysmon tool

`Firewall`
- The scenario uses a Fortinet Fortigate devices as a “Next Generation Firewall” (NGFW). The Fortigate device in this scenario is configured to log network traffic crossing from internal to external, any alerts/blocks, layer 7 protection, and events that the Fortigate device logs

`Stream`
- Stream is Splunk’s wiredata collection/creation tool. It can capture a wide variety of traffic (including PCAPS and payloads!) on a network and turn them into wire metadata that is ingested into Splunk. The sourcetype is broken out into all of the captured/detected protocols (IE stream:dns, stream:http, etc). In this exercise, we have turned on every possible option for Stream so that you can experience the full awesomeness of the tool

`IIS`
- Internet Information Services (IIS) is Microsoft’s default webserver on Windows Server Operating systems. It will show the access and utilization of websites hosted on Windows Web Servers

`Suricata`
- Suricata is a widely used open source IDS similar to Snort. It inspects packets traversing the network and creates alerts based on signatures. In this dataset, we are using a free signature pack provided by Emerging Threats

* WinEventLog:Application
* WinEventLog:Security
* WinEventLog:System
* XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
* fgt_event
* fgt_traffic
* fgt_utm
* iis
* nessus:scan
* stream:dhcp
* stream:dns
* stream:http
* stream:icmp
* stream:ip
* stream:ldap
* stream:mapi
* stream:sip
* stream:smb
* stream:snmp
* stream:tcp
* suricata
* winregistry

## Reconnaissance: BruteForce Attack
Field of Interest:

- source: `stream:http`
- form_data
- http_method
- http_referrer
- site
- src_ip
- src_port
- dest_ip
- dest_port
- src_content
- uri
- uri_path 
- status
- passwd: `multiple`
- username: `single source`
- timestamp
	
SPL of Interest:
- rex
- eval
- stats: `avg()`, count`()`
- timechart
- range: `(_time)`
- transaction 
- table: `duration`

**Extract Target Data**
```
source="stream:http" http_method=POST form_data=*passwd*
| rex field=form_data "username=(?<username>[^&]+)" 
| rex field=form_data "passwd=(?<passwd>[^&]+)"
| eval password_length = len(passwd)
| stats avg(password_length) as avg_password_length
```
**Calculate Frequency**
```
source="stream:http" http_method=POST form_data=*passwd*
| timechart count                     
or
| timechart count dest_ip             
or
| timechart span=1s count by dest_ip  
```
**Calculate Interval**
```
source="stream:http" http_method=POST form_data=*passwd*
| rex field=form_data "username=(?<username>[^&]+)" 
| rex field=form_data "passwd=(?<passwd>[^&]+)"
| search passwd=*batman*
| stats range(_time)
or 
| transaction passwd 
| table duration
```
**Calculate Duration**
```
index=botsv1 sourcetype=stream:http form_data=*username*passwd* | rex field=form_data "passwd=(?<p>\w+)" 
| transaction p
| eval dur=round(duration,2)
| table dur
```
**Check Activity per IP**
```
index=* sourcetype="stream:http" imreallynotbatman.com *passwd*
| transaction src_ip
| table src_ip, form_data
```
**Check Activity Average String Length**
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method="POST" form_data=*username*passwd* 
| rex field=form_data "passwd=(?<p>\w+)" 
| eval pl=len(p) 
| stats avg(pl) as av
| eval avg_count=round(av,0) 
| table avg_count
```

## Reconnaissance: User-Agent Hunting Strings
Field of Interest:
- source: `stream:http`
- http_user_agent 
- http_content_type

SPL of Interest:
- stats `count by http_user_agent`
- sort

```
index="botsv2" sourcetype="stream:http" "TARGET_DOMAIN OR SUSPICIOUS_OS"
| stats count by http_user_agent 
| sort - count
```
```
index="botsv2" sourcetype="stream:http" http_user_agent="*NaenaraBrowser*"
| stats count by src_ip dest_ip
```

Reference:
- [WhatIsMyBrowser - User Agents](https://explore.whatismybrowser.com/useragents/parse/#parse-useragent)
- [Spur - detection of anonymous infrastructure](https://app.spur.us/context?)

## Reconnaissance: Scanning Vulnerability 
Field of Interest:

- source: `stream:http`
- form_data
- http_method
- http_referrer: `check for suspicious tools`
- site
- src_content/src_headers: `check for suspicious tools`
- dest_content/dest_headers
- uri
- uri_path 
- src_ip
- src_port
- dest_ip
- dest_port
- timestamp
	
SPL of Interest:
- rex
- eval
- stats: `values()`
- transaction: `src_ip`
- table

```
source="stream:http" AND site=*imreallynotbatman.com* AND http_method=POST
| transaction src_ip
| table src_ip, uri, src_headers
or
| stats count by src_ip
```
```
source="stream:http" AND site=*imreallynotbatman.com* AND http_method=POST AND src_headers=*SUSPICIOUS_TOOL*
| stats values(src_headers) as src_headers c by src | sort -c
| table src c src_headers
```

## Initial Access: Spear Phishing
Field of Interest:

- source: `stream:smtp`
- attach_filename{}
- attach_type{}
- file_name
- file_hash
- file_type{}
- receiver
- receiver_alias
- receiver_email
- sender
- sender_alias
- sender_email
- src_ip
- dest_ip
- subject
- content_body{}
- content - `check for originating sender and ip`
	
SPL of Interest:
- rex `field=content "sender IP is (?<sender_ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)"`
- stats: `attachment_filename{}`
- transaction: `sender`
- table

```
index=botsv2 sourcetype="stream:smtp" attach_filename{}="invoice.zip"
| transaction sender
| table sender, receiver, subject, content_body{}, attach_filename{}, src_ip, sender_ip, dest_ip
```

## Defense Evasion: Indicator Removal on Host
Fields of Interest:

- EventCode: `*104*` or `*1102*`
- RecordNumber
- Account_Name
- New_Process_Name
- Process_Command_Line

	
SPL of Interest:
- stats: 
- transaction: 
- table
- sort

```
index=botsv2 sourcetype=wineventlog EventCode=1102
```
**Wevtutil Execution sort by Record Number**
```
index=botsv2 wevtutil.exe sourcetype=wineventlog
| table _time EventCode RecordNumber Account_Name New_Process_Name Process_Command_Line
| sort + RecordNumber
```
**Wevtutil Execution without "Process Terminate" Status**
```
index=botsv2 wevtutil.exe sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventDescription!="Process Terminate"
| table _time RecordID host user CommandLine ParentCommandLine
| sort + RecordID
```

## Lateral Movement: WMI at Destination

Fields of Interest:

- event.code: `*1*`
- Account.Name
- user: `NT AUTHORITY\\NETWORK SERVICE`
- Image: `*C:\\Windows\\System32\\wbem\\WmiPrvSE.exe*`
- CommandLine: `*C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding*`

```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 
user="NT AUTHORITY\\NETWORK SERVICE" CommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding" 
Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ParentImage="C:\\Windows\\System32\\svchost.exe" ParentCommandLine="C:\\Windows\\System32\\svchost.exe -k DcomLaunch" EventCode=1
```


## Lateral Movement: Remote Execution (Including WMI)
Fields of Interest:

- sourcetype= `wineventlog` or `sysmon`
- event.code: `*1*` OR `*4624*`
- host
- dest
- Security_ID 
- Logon_ID
- Parent_Process
- Image
- CommandLine

SPL of Interest:
- eval
- transaction
- table

```
(sourcetype=wineventlog (EventCode=4624 Logon_Type=3)) OR (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" ParentCommandLine!="*\\svchost.exe" EventCode=1)
| eval login=mvindex(Logon_ID,1)
| eval user_id=mvindex(Security_ID,1)
| eval session = lower(coalesce(login,LogonId))
| transaction session startswith=(EventCode=4624) mvlist=ParentImage
| search eventcount>1
| eval Parent_Process=mvindex(ParentImage,1)
| table _time dest session host user_id Parent_Process Image CommandLine
```

## Lateral Movement: Inspecting Login Sessions
Fields of Interest:

- sourcetype= `wineventlog` or `sysmon`
- event.code: `*1*` OR `*4624*`
- TaskCategory 
- Account_Name
- Security_ID
- ParentCommandLine
- CommandLine

SPL of Interest:
- eval
- table

```
index="botsv2" ((Logon_ID=0x171491a OR LogonId=0x171491a) host=*TARGET_HOST*)
| eval shortCL=substr(CommandLine,1,100) 
| eval shortPCL=substr(ParentCommandLine,1,100)
| table _time EventCode TaskCategory Account_Name Security_ID Process_Command_Line shortCL shortPCL
```
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  ParentCommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding"
| eval shortCL=substr(CommandLine,1,100)
| table _time user host ProcessId ParentProcessId shortCL ParentCommandLine
```

## Persistence: Short Time Scheduled Tasks (Process)
Fields of Interest:

Process (Sysmon)
- event.code: `*1* `
- ParentImage
- ParentCommandLine: `*powershell*`
- Image: `*schtasks.exe*`
- CommandLine: `*schtasks*`

File Create (Sysmon)
- event.code: `*11*`
- file.path: `C:\Windows\System32\Tasks\{NameOfTask}`

```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 
CommandLine="*schtasks.exe*"
| stats count by CommandLine ParentCommandLine
```
**Sort by Host**
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
 CommandLine="*schtasks.exe*" ParentCommandLine="*powershell*"
| transaction host
| table _time host CommandLine ParentCommandLine
```
**Sort by TaskName**
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
 CommandLine="*schtasks.exe*" 
| rex field=CommandLine "(?i)tn\s+(?<taskname>.*)\s"
| transaction taskname
| table _time, taskname, host, CommandLine, ParentCommandLine
```

## Persistence: Short Time Scheduled Tasks (Registry)
Fields of Interest:

Registry (Windows Security)
- event.code: `*4698*` or `*4699*`
- task.name
- host.name
- user.name
- event.action
- message

Registry (winregistry)
- sourcetype: `*winregistry*`
- registry_type
- key_path
- data_type
- data
- process_image

```
index="botsv2" sourcetype="winregistry" Software\\Microsoft\\Network
```

## Command and Control: Outbound Connection with Suspicious File Retrieval
Field of Interest:

- source: `stream:http`
- c_ip
- src_ip
- http_method: `GET`
- src_ip: `Internal IP`
- dest_port
- dest_ip: `External IP` 
- uri
- uri_path
- url
	
SPL of Interest:
- stats: `count(url/uri)`

**Note: Perform extended checking of the reputation of External IP**
```
source="stream:http" AND src_ip="192.168.250.70"
| stats count by uri
or
| stats count by url
```
```
index=* sourcetype=stream:http c_ip="192.168.250.100"
| stats count by url
```

## Command and Control: Outbound Connection with Suspicious File Download
Field of Interest:

- source: `stream:http` or `stream:http`
- c_ip
- src_ip
- src_ip: `External IP`
- dest_port
- dest_ip: `Internal IP` 
- http_method: `POST`
- method
- `filename=`
	
SPL of Interest:
- rex: `filename`
- stats: `count(url/uri)`

```
index=* imreallynotbatman.com *.exe*  dest="192.168.250.70" 
|  stats count by filename
```
```
index=* sourcetype=stream:http dest="192.168.250.70" "multipart/form-data" 
|  stats count by part_filename{}
```

## Command and Control: Suspicious Traffic
Field of Interest:

- source: `suricata`
- src_ip
- src_ip: 
- dest_port
- dest_ip: 
- method_parameter
- method
- reply_content
	
SPL of Interest:
- rex
- stats

```
sourcetype=suricata AND cerber
| stats count by alert.signature_id
```

## Command and Control: Suspicious Traffic (DNS)
Field of Interest:

- source: `suricata`
- src_ip
- src_ip: 
- dest_port
- dest_ip:  
- record_type
- query
- bytes
	
SPL of Interest:
- transaction
- stats

```
sourcetype="stream:dns" src_ip="192.168.250.100" record_type=A
| transaction src_ip
| table src_ip, dest_ip, query{}
```

## Execution: Malicious Scripting
Field of Interest:

- sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- eventcode=`1`
- host
- Computer
- CommandLine
- Image
- ParentCommandLine
- ParentImage
- user
- ParentProcessId
- ProcessId

SPL of Interest:
- transaction
- eval

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 *vbs* *js* *jse*
| transaction ParentImage
| eval lenCMD = len(CommandLine)
| table ParentImage, ParentCommandLine, Image, CommandLine, lenCMD
```

## Execution: Malicious Process Execution
Field of Interest:

- sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- eventcode=`1`
- host 
- Computer
- CommandLine
- Image
- ParentCommandLine
- ParentImage
- user
- ParentProcessId
- ProcessId

SPL of Interest:
- transaction
- eval

**Sort by Parent CommandLine and Image**
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Computer="venus.frothly.local"
| transaction ParentImage
| table ParentImage, ParentCommandLine, Image, CommandLine
```
**Sort by initial execution of Parent CommandLine and Image**
```
*ARTIFACT* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine=*
| table _time, CommandLine, ProcessId, ParentCommandLine, ParentProcessId 
| reverse
```

## Initial Access: USB 
Field of Interest:

- sourcetype: `WinRegistry`
- registry_value_name
- registry_key_name
- registry_path
- registry_value_data
- dest

Reference:
[USB device registry entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-specific-registry-settings)
[USB Forensics: Find the History of Every Connected USB Device on Your Computer](https://www.cybrary.it/blog/usb-forensics-find-the-history-of-every-connected-usb-device-on-your-computer)
```
sourcetype=WinRegistry host="we8105desk" registry_value_name=friendlyname
```

## Impact: File Decryption 
Field of Interest:

sourcetype: `WinEventLog:Security`
- Event Code: `5145` 
- Account Name
- Share Name:	`\\*\fileshare`
- Share Path:	`\??\C:\fileshare`
- Access Mask: `0x12019F`
- Relative Target Name: `Target FileName`

sourcetype: `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- Event Code: `2`
- TargetFilename
- direction
- dvc

SPL of Interest:
- dedup
- table
- stat

```
host="we9041srv" sourcetype="WinEventLog:Security" EventCode="5145" Source_Address="192.168.250.100" Account_Name="bob.smith" Share_Name="\\\\*\\fileshare" Relative_Target_Name="*.pdf" Access_Mask=0x12019F
| dedup Relative_Target_Name
| table Relative_Target_Name
```
```
host="we8105desk" ".txt" EventID="2" file_path="C:\\Users\\bob.smith.WAYNECORPINC*" 
| dedup file_path 
| stats count as unique_count
```

## Resource Development: SSL Fingerprints for Threat Hunting
Field of Interest:

sourcetype: `suratica`
- ssl_subject_common_name
- tls.fingerprint
- tls.issuerdn
- src_ip
- dest_ip


SPL of Interest:
- transaction
- table

**Pivoting of Indicator**
```
index="botsv2" "C=US" sourcetype=suricata 
| transaction dest_ip
| table dest_ip, src_ip, ssl_subject_common_name
or
| stats count by dest_ip, ssl_subject_common_name, tls.fingerprint
| table dest_ip, ssl_subject_common_name, tls.fingerprint, count

Note: you may remove ssl subject common name on initial query.
```
```
index="botsv2" "C=US" sourcetype=suricata 
| transaction ssl_subject_common_name, dest_ip
| dedup ssl_subject_common_name, dest_ip 
| table ssl_subject_common_name, dest_ip, src_ip, _time
```

```
index="botsv2" 'TARGET_IP' sourcetype='AVALIABLE_SOURCETYPE'
| stats count by src_ip dest_ip
| sort - count
```
## Collection: SMB
Field of Interest:

sourcetype: `stream:smb`
- dest_ip
- src_ip
- bytes
- filename
- command
- flowid

SPL of Interest:
- transaction
- table
- eval `uniq=src_ip." ".dest_ip`
- timechart `count by uniq`


```
index="botsv2" 160.153.91.7
| stats count by sourcetype
```
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls) sourcetype="stream:smb"
| stats count by sourcetype
| sort - count
```
**Source and Destination Overtime**
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls) sourcetype="stream:smb"
| eval uniq=src_ip." ".dest_ip
| timechart count by uniq
```
**Count By Filenames And Sort By Unique Flow ID**
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls) sourcetype="stream:smb" 
| transaction flow_id, dest_ip 
| eval total_filenames=mvcount(filename) 
| table flow_id, dest_ip, src_ip, command, total_filenames
AND
index="botsv2" flow_id="d7370639-8ca9-40d3-a5f8-dd6547d4ff99" sourcetype="stream:smb" 
| stats count by command
```
**Sort By Sum of Bytes In and Out**
```
index="botsv2" sourcetype="stream:smb" flow_id=d7370639-8ca9-40d3-a5f8-dd6547d4ff99  command="smb2 read"
| stats count sum(bytes_in) AS b_in sum(bytes_out) AS b_out by src_ip dest_ip
```
**Sort via Destination**
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls) sourcetype="stream:smb"
| transaction dest_ip
| table dest_ip, src_ip, command, bytes, filename
```
**Most Frequently Seen Files**
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls) sourcetype="stream:smb"
| stats count by src_ip, dest_ip, filename
| sort - count
```

## Exfiltration: FTP
Field of Interest:

sourcetype: `stream:ftp`
- dest_ip
- src_ip
- method
- reply_code
- reply_content
- filename
- loadway: `Upload` or `Download`
f


SPL of Interest:
- transaction
- table


```
index="botsv2" 160.153.91.7
| stats count by sourcetype
```
```
index="botsv2" (.pdf OR .tgz OR .doc OR .xls)
| stats count by sourcetype
| sort - count
```

**Network Communication Flows**
```
index="botsv2" 160.153.91.7  sourcetype="stream:ftp"
| transaction dest_ip
| table dest_ip, src_ip, method, reply_code, reply_content, filename

```
**Filter Upload Activity**
```
index="botsv2" 160.153.91.7  sourcetype="stream:ftp" loadway=Upload
| transaction dest_ip
| table dest_ip, src_ip, method, reply_code, reply_content, filename
```
**Filter Download Activity**
```
index="botsv2" 160.153.91.7  sourcetype="stream:ftp" loadway=Download
| transaction dest_ip
| table dest_ip, src_ip, method, reply_code, reply_content, filename
```

Field of Interest:

sourcetype: `wineventlog` or  `xmlwineventlog:microsoft-windows-sysmon/operational`
- Event Code: `1` or `4688`
- host 
- Computer
- CommandLine
- Image
- ParentCommandLine
- ParentImage
- user
- ParentProcessId
- ProcessId

SPL of Interest:
- transaction
- table

**Host Communication Flows**
```
index=botsv2 "ftp" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 
| transaction host
| table host CommandLine
```
```
index=botsv2 ftp sourcetype="wineventlog" 
| transaction host
| table host Process_Command_Line
```

## Exfiltration: DNS
Field of Interest:

sourcetype: `stream:ftp`
- dest_ip
- src_ip
- hostname
- query
- bytes_in
- bytes_out

SPL of Interest:
- transaction
- table
- stats

```
index="botsv2" sourcetype="stream:dns" hildegardsfarm.com
| timechart span=1s count by dest_ip
```
```
index="botsv2" sourcetype="stream:dns" hildegardsfarm.com 
| transaction dest_ip
| table dest_ip, src_ip, hostname{}, query{}, bytes_in, bytes_out
```

# ELK
Elastic's ELK is an open source stack that consists of three applications (Elasticsearch, Logstash and Kibana) working in synergy to provide users with end-to-end search and visualization capabilities to analyze and investigate log file sources in real time.

ELK Stack 
- Elasticsearch – index storage and search backend
- Logstash – used to shape logs and ship logs to Elasticsearch
- Kibana – GUI frontend for search, visualization, dashboards, reporting and alerting, and Elastic stack cluster management
- Beats – Lightweight log shippers that are installed on endpoints

# ELK - Visualization

- Home > Visualization
- Click the Create Visualization
- Click the Vertical Bar > *target_log*

Now we have our Metrics and Buckets. Sample Configuration for Top 10 Agent Hostname:

- **Metrics**: Y-axis
- **Buckets**: X-axis
- **Aggregation**: Terms
- **Field**: agent.hostname / host.name.keyword
- **Order** by: Metric: Count
- **Order**: Descending
- **Size**: 10
- **Custom Label**: Top 10 Agent Hostname

Go to Dashboard and add all of your visualized charts.

Note: On the search bar part, you may see there's a **KQL** there. KQL stands for
Kibana Query Language. Make sure to enable KQL for every session for better search usage.

# ELK - Intel-driven Threat Hunting
- [mitre_attack_xml_eventlogs](https://github.com/BoredHackerBlog/mitre_attack_xml_eventlogs/tree/db5699e016a223c31d34a6d3024ac9cd33d87f52?tab=readme-ov-file) - MITRE ATTACK evtx samples from EVTX-to-MITRE-Attack & EVTX-ATTACK-SAMPLES repos in XML format
- [EVTX-ATTACK-SAMPLES](https://github.com/Lichtsinnig/EVTX-ATTACK-SAMPLES/tree/57395181405d5e3e91edfb70c7ffefad4fcfc04f) - This is a container for windows events samples associated to specific attack and post-exploitation techniques
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Atomic Red Team is a library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.
- [MITRE Cyber Analytics Repository](https://car.mitre.org/analytics/by_technique)- The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the MITRE ATT&CK adversary model.
- [Threat Hunter Playbook](https://threathunterplaybook.com/intro.html) - The Threat Hunter Playbook is a community-driven, open source project to share detection logic, adversary tradecraft and resources to make detection development more efficient. 
- [Alerta Temprana de Amenazas de Seguridad con Apache Kafka y la Pila ELK](https://uvadoc.uva.es/bitstream/handle/10324/50431/TFG-G5267.pdf?sequence=1)

## Execution: Rundll32
Fields of Interest:

- process.name: `rundll32.exe`
- process.args:`*pcwutl.dll*` `*LaunchApplication*`
- process.args:`("*\\rundll32.exe* url.dll,*OpenURL *" "*\\rundll32.exe* url.dll,*OpenURLA *" "*\\rundll32.exe* url.dll,*FileProtocolHandler *" "*\\rundll32.exe* zipfldr.dll,*RouteTheCall *" "*\\rundll32.exe* Shell32.dll,*Control_RunDLL *" "*\\rundll32.exe javascript\:*" "* url.dll,*OpenURL *" "* url.dll,*OpenURLA *" "* url.dll,*FileProtocolHandler *" "* zipfldr.dll,*RouteTheCall *" "* Shell32.dll,*Control_RunDLL *" "* javascript\:*" "*.RegisterXLL*")`

Reference:
- [win_susp_rundll32_activity.yml](https://gist.github.com/curi0usJack/14d1b2062691c0a50c4dae6f29001107)

## Execution: URL.dll/IEFrame.dll
Fields of Interest:

- event.code: `*1*` 
- winlog.event_data.ParentImage
- process.name: `rundll32.exe`
- process.args:`(url.dll OR ieframe.dll)` AND `(FileProtocolHandler OR OpenURLA)`

## Execution: Pcwutl
Fields of Interest:

- event.code: `*1*` 
- winlog.event_data.ParentImage
- process.name: `rundll32.exe`
- process.args:`*pcwutl.dll*` `*LaunchApplication*`

Reference:
- [LOLBIN - Pcwutl.dll](https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/)

## Execution: Squiblydoo
Fields of Interest:

- event.code: `*1*` 
- winlog.event_data.ParentImage
- winlog.event_data.ParentCommandLine: `*scrobj*` `*regsvr32*`
- winlog.event_data.Image
- winlog.event_data.CommandLine: `*scrobj*` `*regsvr32*`
- agent.hostname
- winlog.computer_name

## Execution: Mshta

- event.code: `*1*` 
- winlog.event_data.ParentImage
- process.name: `rundll32.exe`
- process.args:`*mshtml*` `*RunHTMLApplication*`

## Execution: Spearphishing Attachment / MalDoc
Fields of Interest:

- event.code: `*1*` or `*4688*`
- process.parent.executable : `*winword.exe*`
- process.executable : `*powershell.exe* OR *cmd.exe*`
- Time
- winlog.computer_name
- winlog.user.name
- agent.hostname / host.name

## Persistence: Short Time Scheduled Tasks
Fields of Interest:

Process (Sysmon)
- event.code: `*1* `
- process.parent.executable
- process.parent.args
- process.executable: `*schtasks.exe*`
- process.args: `*schtasks*`

File Create (Sysmon)
- event.code: `*11*`
- file.path: `C:\Windows\System32\Tasks\{NameOfTask}`

Registry (Windows Security)
- event.code: `*4698*` or `*4699*`
- task.name
- host.name
- user.name
- event.action
- message

**OTHER INDICATORS** 

Tasks running scripts or programs from temp directories or insecure locations (writable by any user) are a good indicator for initial (malware just landed) execution/persistence via
scheduled tasks, includes but not limited to the following locations:
```
1. c: \users\*
2. c:\programdata\*
3. c:\windows\temp\*
```

For scripting utilities pay attention to tasks with action set to one
of the following (inspect the arguments if they point to the below
insecure commonly used paths):

```
1. cscript.exe
5. wmic.exe
2. wscript.exe
6. cmd.exe
3. rundl132.exe
7. mshta.exe
4. regsvr32.exe
8. powershell.exe
```

## Persistence: DCSync Attack
Fields of Interest:

An operation was performed on an object (Windows Security)
- event.code: `*4662*` 
- AccessMask: `*0x100*`
- OperationProperties:
  - `*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*`
  - `*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*`
  - `*9923a32a-3607-11d2-b9be-0000f87a36b2*`
  - `*89e95b76-444d-4c62-991a-0facbeda640c*`
- SubjectUserName|endswith: `NOT *$*`

**Key Indicators**

When `Add-DomainObjectAcl` is used to to grant DCSync rights, the following ACEs are added to the DACL and the associated GUIDs are recorded in `Event ID 5136` logs.

- DS-Replication-Get-Change
  - GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- DS-Replication-Get-Changes-All
  - GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

These same GUIDs are recorded in `Event ID 4662` logs under the `"properties"` field when DCSync is used. Note that we have mutated this field to `"object.properties"` in our environment.

Look for the following Event IDs, filter for the GUIDs above, and group by time:
- **Event ID 5136**- an AD object was modified
  - filter on the GUIDs above
- **Event ID 4662** - an AD object was accessed
  - search for account names not belonging to domain controllers to identify user account that performed sync operations

```
Keep in mind that if DCSync is used from a DC account there will be no
log of the event. Also, even with the above indicators, further
analysis is required to identify a source IP. One method is to conduct
network traffic analysis on the DC of interest then deconflict other
known DC IPs. Another method is to use SQL to join 4662 and 4624 logs
based on the TargetLogonId value.
```

**Destination**
- event.code: `*4662*` or `*5136*`
- OperationProperties:
  - `*1131f6a*-9c*11d1-f79f-00c04fc2dcd2*`

Reference:
- [DCSync Detection, Exploitation, and Detection](https://www.linkedin.com/pulse/dcsync-detection-exploitation-debashis-pal/)
- [Detects Mimikatz DC sync security events](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/builtin/security/win_security_dcsync.yml#L26)

## Persistence: BitsAdmin
Key Indicators
- **EventID 3** - A bits job was created
- **EventID 59** - A bits job was started
- **EventID 60** - A Bits job was stopped

Fields of Interest:

- event.code: `*3*` OR `*59*` OR `*60*`
- channel
- event.action: `*BITS*`
- bytesTransferred
- url
- message

## Privelege Escalation: UAC Bypass Using SDCLT.EXE
Fields of Interest:

Registry (Sysmon)
- event.code: `*13*` 
- registry.key.path: `*IsolatedCommand*`
- registry.key.value: 

Process (Sysmon)
- event.code: `*1*` 
- process.parent.executable
- process.parent.args
- registry.key.path: 
- process.executable: 
- process.args: `*sdclt.exe*` `*/Kickoffelev*`

Reference:
- ["FILELESS" UAC BYPASS USING SDCLT.EXE](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
- [Bypasses UAC by hijacking the "IsolatedCommand" value in "shell\runas\command"](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-SDCLTBypass.ps1)


## Privilege Escalation: UAC Bypass Using cliconfg (DLL - NTWDBLIB.dll)
Fields of Interest:

FileCreate or ModuleLoad(Sysmon)
- event.code: `*11*` OR `*7*` 
- file.path: `NTWDBLIB.dll`
- process.executable: 

```
python, winpwnage.py, -u, uac, -i, 11, -p, c:\Users\IEUser\Desktop\hellox86.dll
```
Reference:
- https://github.com/vaginessa/WinPwnage-2


## Privilege Escalation: UAC Bypass using CompMgmtLauncher
Identifies use of CompMgmtLauncher.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.

Fields of Interest:

Registry (Sysmon)
- event.code: `*13*` 
- registry.key.path: `"\\mscfile\\shell\\open\\command"`
- registry.key.value: 
- event.action

Process (Sysmon)
- event.code: `*1*` 
- process.parent.executable
- process.parent.args
- registry.key.path: 
- process.executable: 
- process.args: `*CompMgmtLauncher.exe*`
- event.action

Reference:
[Bypass UAC via CompMgmtLauncher](https://eqllib.readthedocs.io/en/latest/analytics/7efc7afe-8396-4bf0-ac7d-1a860a401d22.html)


## Defense Evasion: Indicator Removal on Host
Fields of Interest:

- event.code: `*104*` or `*1102*`
- Time
- winlog.computer_name
- winlog.channel
- agent.hostname / host.name
- user.name


## Defense Evasion: RDP Settings Tampering
Fields of Interest:

- event.code: `*1*`
- file.path: `*netsh*`
- process.args: `*netsh*` `*advfirewall*` `*localport=3389*` `*action=allow*`

Reference:
- [RDP Wrapper Library by Stas'M](https://github.com/stascorp/rdpwrap)

```
C:\Users\IEUser\Desktop\RDPWrap-v1.6.2\RDPWInst, -i, -o
```
```
netsh, advfirewall, firewall, add, rule, name=Remote Desktop, dir=in, protocol=tcp, localport=3389, profile=any, action=allow
```

## Defense Evasion: Java DLL Sideloading
**Key Indicators**

When analyzing Sysmon logs, look for indications of Java programs with interesting behavior such as:
- executing from a directory other than the Java home directory
- loading legitimate DLL from an other-than-expected path
- script processes spawning an unsigned binary
- Service Host process (svchost.exe) spawned by an unexpected parent
- exporting registry hives

Look for the following Sysmon events:
- **Event ID 1** - A process was created
- **Event ID 7** - A module was loaded
- **Event ID 8** - A remote thread was created
- **Event ID 13** - A registry value was modified


## Credential Access: INVOKE-MIMIKATZ
**Key Indicators**

Begin by filtering on the indicators below:
- **Event ID 10 **- A process was accessed
- **lsass.exe**

Fields of Interest:

- event.code: `*1*`
- target.image: `*lsass.exe*`
- process.args: `0x143A` OR `0x1010` OR `0x1410` OR `0x1438`

Reference
- [Threat Hunter Plyabook - Mimikatz OpenProcess Modules](https://threathunterplaybook.com/library/windows/mimikatz_openprocess_modules.html?highlight=1438)

An **access mask** is a 32-bit value whose bits correspond to the access rights supported by an object. Different versions of Mimikatz in the wild have been observed using the access masks below. Note that our Logstash configuration mutates the Sysmon Granted Access log field to "process.granted_access" which may be named differently elsewhere.

| module                                                                          | ACCESS_MASK translated | OpenProcess caller function                                                  | destination process / destination service | ACCESS_MASK                                                                                                       | comment                                                                                                                                                                                                                                                                                                                                                                                                                      |
|---------------------------------------------------------------------------------|------------------------|------------------------------------------------------------------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| sekurlsa::*                                                                     | 0x1410                 | kuhl_m_sekurlsa_acquireLSA()                                                 | lsass.exe                                 | PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION                                                                      | for Windows Version < 5                                                                                                                                                                                                                                                                                                                                                                                                      |
| sekurlsa::*                                                                     | 0x1010                 | kuhl_m_sekurlsa_acquireLSA()                                                 | lsass.exe                                 | PROCESS_VM_READ \| PROCESS_QUERY_LIMITED_INFORMATION                                                              | for Windows Version >= 6                                                                                                                                                                                                                                                                                                                                                                                                     |
| lsadump::lsa /patch                                                             | 0x1438                 | kuhl_m_lsadump_lsa_getHandle()                                               | SamSs                                     | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| lsadump::lsa /inject                                                            | 0x143a                 | kuhl_m_lsadump_lsa_getHandle()                                               | SamSs                                     | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION \| PROCESS_CREATE_THREAD |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| lsadump::trust /patch                                                           | 0x1438                 | kuhl_m_lsadump_lsa_getHandle()                                               | SamSs                                     | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| minesweeper::infos                                                              | 0x1418                 | kuhl_m_minesweeper_infos()                                                   | minesweeper.exe                           | PROCESS_VM_READ \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                                              |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| misc:detours                                                                    |                        | kuhl_m_misc_detours_callback_process()                                       | *                                         | GENERIC_READ                                                                                                      | omitted because of the very generic ACCESS_MASK                                                                                                                                                                                                                                                                                                                                                                              |
| misc:memssp                                                                     | 0x1438                 | kuhl_m_misc_memssp()                                                         | lsass.exe                                 | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| process::suspend, process:stop, process:resume,process:imports, process:exports |                        | kuhl_m_process_genericOperation()                                            |                                           |                                                                                                                   | omitted because of the very generic ACCESS_MASKs                                                                                                                                                                                                                                                                                                                                                                             |
| vault::cred /patch                                                              | 0x1438                 | kuhl_m_vault_cred()                                                          | SamSs                                     | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| token::list, token::elevate, token::run                                         | first 0x1400 then 0x40 | querying all processes on the system                                         | *                                         |                                                                                                                   | all three commands result in a call to kull_m_token_getTokens() which first iterates over all processes and threads with OpenProcess(PROCESS_QUERY_INFORMATION (0x1400)) (kull_m_token_getTokens_process_callback()) and then again to get the tokens OpenProcess(PROCESS_DUP_HANDLE (0x40)) (in kull_m_handle_getHandlesOfType_callback()) to duplicate the Tokens. This results in many thousand (!) Events with ID 10 (!) |
| crypto::cng                                                                     | 0x1438                 | kull_m_patch_genericProcessOrServiceFromBuild() via kuhl_m_crypto_p_cng()    | KeyIso                                    | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| event::drop                                                                     | 0x1438                 | kull_m_patch_genericProcessOrServiceFromBuild() via kuhl_m_event_drop()      | EventLog                                  | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          | ** this event does not get logged! :O mimikatz seems to be fast enough to apply the patch before the event gets logged!**                                                                                                                                                                                                                                                                                                    |
| misc::ncroutemon                                                                | 0x1438                 | kull_m_patch_genericProcessOrServiceFromBuild() via kuhl_m_misc_ncroutemon() | dsNcService                               | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ts::multirdp                                                                    | 0x1438                 | kull_m_patch_genericProcessOrServiceFromBuild() via kuhl_m_ts_multirdp()     | TermService                               | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION                          |                                                                                                                                                                                                                                                                                                                                                                                                                              |

## Credential Access: Credential Dumping
Fields of Interest:

- event.code: `*1*` or `*4688*`
- Time 
- process.parent.executable 
- process.executable
- process.parent.command_line: `*.dmp*` `*lssas*`
- process.command_line 
- agent.hostname / host.name
- winlog.user.name

## Credential Access: Credential Dumping thru Fileless Attack
Fields of Interest:

- event.code: `*1*` or `*4688*`
- Time 
- process.parent.executable 
- process.executable
- process.parent.command_line: `*mimikatz*` `*DumpCreds*`
- process.command_line 
- agent.hostname / host.name
- winlog.user.name


## Discovery: Network Share Enumeration
Key Indicators
Filter on specific Sysmon Event IDs and common named pipes, looking for local and remote domain SMB sessions.

Event IDs 
- **Event ID 3** - A TCP or UDP connection was made
- **Event ID 18** - A named pipe connection was made between a client and a server
- **Event ID 5145** - A network share object was checked to see whether client can be granted desired access

Common Named Pipes
- **\samr** - user management (SAM) functions
- **\srvsvc** - server management
- **\lsarpc** - local security authority
- **\winreg** - Windows registry

Fields of Interest:

Network (Sysmon)
- event.code: `*3*` 
- source.domain: 
- destination.domain: 
- user.name
- event.action

Pipe Connected (Sysmon)
- event.code: `*18*` 
- file.name: `\samr` OR `\srvsvc` OR `\lsarpc` OR `\winreg`
- event.action

Object Access - Detailed File Share (Windows Security)
- Event Code: `5145`
- Relative Target Name: `\samr` OR `\srvsvc` OR `\lsarpc` OR `\winreg`
- Share Name: `IPC$`
- Access_Mask: `0x12019f`


Look for rare occurrences of **source machine**, **destination machine**, and **users** - a good approach if you know what you're looking for.

Another approach is to look for chains of events generated by the net command. Benign share access looks different then if everything is accessed in a short amount of time. 

Often, attackers launch PowerShell scripts or use Remote Access Tool (RAT) features to
automate comprehensive enumeration.
```
What's a named pipe? - A named pipe is a logical connection, similar to a TCP
session, between a client and server that are involved in a Common Internet
File System (CIFS)or SMB connection. The name of the pipe serves as the
endpoint for communication in the same way that a port number serves as the
endpoint for TCP sessions.
```

## Reconnaissance: Domain Admins or Group Enumeration
Detects activity as "net user administrator /domain" and "net group domain admins /domain"

Fields of Interest:

**Source**: 
```
  net user administrator /domain
```

**Destination:**
  - Event Code: `4661`
  - Object Type: `SAM_USER`
  - Object Name: `S-1-5-21-*-500 (* represents domain)`
  - Access Mask: `0x2d `
  
**Note**: In my testing, users in the Domain Admins group will display a SID.  Other users will not. The exception is the Guest and krbtgt accounts.  I would also pay attention to the krbtgt `SID S-1-5-21-*-502`.  I would think that it would be very odd to see this and may indicate an attacker is intending to use Golden Tickets.

**Source**: 
```
  net group "Domain Admins" /domain
```
**Destination:**
    Event Code: `4661`
    Object Type: `SAM_GROUP`
    Object Name: `S-1-5-21-*-512`
    Access Mask: `0x2d`
**Note**: Also pay attention to the Enterprise Admins group with the SID of `S-1-5-21-*-519`

The following can be used to identify **PowerSploit's** `Get-NetSession`, `Get-NetShare`, `netsess.exe` and `net view`.  The `net view` command may look something like 
```
net view \\192.168.56.10
```

**Destination**:
  - Event Code: `5145`
  - Relative Target Name: `srvsvc`
  - Share Name: `IPC$`
  - Access_Mask: `0x12019f`

**Note**: These events may be very loud.  I would suggest looking for a single source creating srvsvc pipes on multiple machines within a specified time frame.  This may be indicative of enumeration activity.

## Lateral Movement: PsExec Usage
**Key Indicators**

PSExec service creation (Windows Event ID 7045) and EULA-related remote registry changes are both known indicators, however note that these can be bypassed using the `PsExec -r (rename)` flag or `PsExec Python and PowerShel`l versions, respectively.

One dependable approach to detection is to filter on the following Windows Event ID which logs the relative target name field traces of remote access to `PSEXECSVC` named pipes:

- **Event ID 5145** - A network share object was checked to see whether client can be granted desired access

From here, wildcard search for target names ending in `"stdin"`, `"stdout"`, or `"stderr"`; these strings are consistently appended to PsExec services regardless if they are renamed. Be aware that we use the field name `"share.relative_target_name"` which may be different than what's used in other environments.

Fields of Interest:

**Destination**:
  - Event Code: `5145`
  - Relative Target Name: `"*-stdin"` OR `"*-stdout"` OR `"*-stderr"`
  - Share Name: `IPC$`
  - Access_Mask: `0x12019f`

```
Did you know? - Event ID 5145 is logged when the Detailed File Share
setting is enabled in the Windows Audit logging policy. This setting
logs an event every time a file or folder is accessed, whereas the
File Share setting only records one event for any connection
established between a client and file share. Detailed File Share audit
events include detailed information about the permissions or other
criteria used to grant or deny access.
```

## Lateral Movement: WMIExec Usage

**Key Indicators**

Search for the following Sysmon Event IDs then group logs generated within 1
minute of each other.
- **Event ID 1** - A process was created
- **Event ID 3** - A TCP/UDP connection was made

When `WMI` is used for remote access, Sysmon logs a network connection and instances of child process creations with `wmiprvse.exe` as the parent process. Look for `cmd.exe` and `powershell.exe` child processes then investigate process arguments for potentially malicious commands.

Fields of Interest:

- event.code: `*1*` 
- process.parent.executable : `*wmiprvse.exe*`
- process.executable : `*powershell.exe* OR *cmd.exe*`
- Time
- winlog.computer_name
- winlog.user.name
- agent.hostname / host.name


## Lateral Movement: Possible Remote WMI Abuse - Mimikatz (Remote Login)
Fields of Interest:

A logon was attempted using explicit credentials (Windows Security)
- event.code: `*4648*`
- Account.Name
- Account.Domain
- process.executable: `*C:\Windows\System32\svchost.exe*`
- process.executable: `*C:\Windows\System32\wbem\WMIC.exe*`

[Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-Mimikatz.htm)

## Impact: Inhibit System Recovery - Vssadmin 
Fields of Interest:

- event.code: `*1*` or `*4688*`
- Time
- process.working_directory 
- process.parent.executable: `*cmd*`
- process.executable: `*vssadmin*`
- process.command_line: `*vssadmin*` `*delete*` `*shadows*` 
- agent.hostname / host.name

## Credential Attack
Fields of Interest:

- event.code: `*4625*`
- Time
- agent.name / winlog.computer_name
- user.name
- winlog.event_data.LogonType
- winlog.event_data.FailureReason
- winlog.logon.failure.reason
- winlog.logon.failure.sub_status

## Remote Login Sessions
Fields of Interest:

- event.code: `*4624* (Logon Successful)`
- event.code: `*4625* (Failed Logon)`
- winlog.event_data.LogonType: `*10*`
- Time
- agent.name / winlog.computer_name
- user.name
- winlog.logon.type

## Network Monitoring IP
Fields of Interest:

- event.code: `*3*`
- Time	
- agent.name	
- agent.hostname / host.name
- winlog.computer_name	
- process.executable	
- user.name	
- destination.domain

## Network Monitoring Domain
Fields of Interest:

- event.code: `*3*`
- Time	
- agent.name	
- winlog.computer_name	
- agent.hostname / host.name
- process.executable	
- user.name	
- source.ip	
- source.port	
- destination.ip	
- destination.port

## Powershell Generic
Fields of Interest:

- event.code: `*4104*`
- Time
- winlog.event_data.ScriptBlockText: 
- winlog.event_id
- winlog.computer_name
- agent.hostname / host.name

### Framework
- winlog.event_data.ScriptBlockText: (PowerUp OR Mimikatz OR NinjaCopy OR Get-ModifiablePath OR AllChecks OR AmsiBypass OR PsUACme OR Invoke-DLLInjection OR Invoke-ReflectivePEInjection OR Invoke-Shellcode OR Get-GPPPassword OR Get-Keystrokes OR Get-TimedScreenshot OR PowerView)

### Compression
- event.code: `*4104*`
- winlog.event_data.ScriptBlockText: `*decompress*`

- [Base64 Encoded File Signatures](https://malware.news/t/base64-encoded-file-signatures/27375)
**File Signatures**
File signatures, aka 'magic bytes' or 'file headers', are static bytes that appear at the start of files.

| File type                        | File Signature          | Base64Encoding |
|----------------------------------|-------------------------|---------------:|
| DOS Executable                   | MZ                      |             TV |
| RAR Compressed                   | Rar!                    |          UmFyI |
| PDF                              | %PDF                    |          JVBER |
| Office/Zip                       | PK                      |             UE |
| Rich Text Format                 | {\rtf                   |         e1xydG |
| Compound Binary File (.doc etc.) | D0 CF 11 E0 A1 B1 1A E1 |     0M8R4KGxGu |
| Gzip                             | 1F 8B 08                |           H4sI |

**Common Script Elements**
These script elements are common leading commands that can be encountered during script analysis.
| Script Element | Base64 Encoding |
|----------------|-----------------|
| http           | aHR0c           |
| $\x00          | JA              |
| iex (          | aWV4IC          |
| cmd.exe /      | Y21kLmV4ZSAv    |
| certutil       | Y2VydHV0aW      |
| wscript        | d3Njcmlwd       |
| schtasks       | c2NodGFza3      |
| eval           | ZXZhb           |


### Encoded
Process (Sysmon)
- event.code: `*1*`
- winlog.event_data.CommandLine: `(-Encodedcommand or -Enc or -eNco or -^e^C^ or -ec)`

ScriptBlockText Logging (Powershell)
- event.code: `*4104*`
- winlog.event_data.ScriptBlockText: `(*xor* or *char* or *join* or *ToInt* or *ToDecimal* or *ToString*)`

### Download
- event.code: *4104*
- winlog.event_data.ScriptBlockText: `(*WebClient* OR *DownloadData* OR *DownloadFile* OR *DownloadString* OR *OpenRead* OR *WebRequest* OR *curl* OR *wget* OR *RestMethod* OR *WinHTTP* OR *InternetExplorer.Application* OR *Excel.Application* OR *Word.Application* OR *Msxml2.XMLHTTP* OR *MsXML2.ServerXML* OR *System.XML.XMLDocument* OR *BitsTransfer*)`

### Execute-Assembly
- winlog.event_data.ScriptBlockText: `*Reflection.Assembly* or *Load* or *ReadAllBytes*`


