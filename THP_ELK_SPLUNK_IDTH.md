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
- [mitre_attack_xml_eventlogs](https://github.com/BoredHackerBlog/mitre_attack_xml_eventlogs/tree/db5699e016a223c31d34a6d3024ac9cd33d87f52?tab=readme-ov-file) - MITRE ATTACK evtx samples from EVTX-to-MITRE-Attack & EVTX-ATTACK-SAMPLES repos in XML format
- [EVTX-ATTACK-SAMPLES](https://github.com/Lichtsinnig/EVTX-ATTACK-SAMPLES/tree/57395181405d5e3e91edfb70c7ffefad4fcfc04f) - This is a container for windows events samples associated to specific attack and post-exploitation techniques
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Atomic Red Team is a library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.
- [MITRE Cyber Analytics Repository](https://car.mitre.org/analytics/by_technique)- The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the MITRE ATT&CK adversary model.
- [Threat Hunter Playbook](https://threathunterplaybook.com/intro.html) - The Threat Hunter Playbook is a community-driven, open source project to share detection logic, adversary tradecraft and resources to make detection development more efficient. 
- [Alerta Temprana de Amenazas de Seguridad con Apache Kafka y la Pila ELK](https://uvadoc.uva.es/bitstream/handle/10324/50431/TFG-G5267.pdf?sequence=1)

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

## BruteForce: Logon attempts using a non-existing account (Kerberos)

`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4768*`
- Status=`0x6` - This value means that the submitted username does not exist.
- TargetUserName 
- IpAddress
- Computer
- eventcount

`SPL of Interest:`
- eval
- table
- transaction `IpAddress maxpause=5m maxevents=-1`
- sort

```
index=ad_hunting EventCode=4768 Status=0x6
| transaction IpAddress 
| table IpAddress TargetUserName ServiceName Computer eventcount
```
```
index="ad_hunting" sourcetype=XmlWinEventLog EventCode=4768 Status=0x6 
| transaction IpAddress maxpause=5m maxevents=-1 
| where eventcount > 5 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| eval accounts=mvcount(TargetUserName) 
| where accounts > 2
| table _time, host, Source, TargetUserName, accounts, eventcount 
| sort - _time  
| convert ctime(Time)
```

## BruteForce: Logon attempts using a non-existing account (NTLM)

`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4776*`
- Status=`0xc0000064` - This value means that the submitted username does not exist.
- TargetUserName 
- Workstation
- eventcount
- host

`SPL of Interest:`
- eval
- table
- transaction `Workstation maxpause=5m maxevents=-1` 
- sort

```
index=ad_hunting EventCode=4776 Status=0xc0000064
| transaction TargetUserName
| where eventcount < 10
| table _time, host, Computer, TargetUserName, eventcount 
| sort - eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4776 Status=0xC0000064 
| transaction Workstation maxpause=5m maxevents=-1 
| where eventcount > 5 
| eval accounts=mvcount(TargetUserName) 
| where accounts > 2 
| table _time, host, Workstation, TargetUserName, accounts, eventcount 
| sort - _time 
| convert ctime(Time)
```

## BruteForce: Excessive failed password attempts from one source (Kerberos)

`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4771*`
- Status=`0x18` - Invalid pre-authentication information, usually a wrong password.
- TargetUserName 
- Computer
- eventcount
- host

`SPL of Interest:`
- eval
- table
- transaction `IpAddress maxpause=5m maxevents=-1` 
- sort

```
index=* EventCode=4771 Status=0x18
| transaction IpAddress 
| table IpAddress TargetUserName, Computer, eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4771 Status=0x18 
| transaction IpAddress maxpause=5m maxevents=-1 
| where eventcount > 5 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| eval accounts=mvcount(TargetUserName) 
| table _time, host, Source, TargetUserName, accounts, eventcount 
| sort - _time 
| convert ctime(Time)
```

## BruteForce: Excessive failed password attempts from one source (NTLM)

`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4776*`
- Status=`0xC000006A` - A logon with misspelled or wrong password.
- TargetUserName 
- Workstation
- eventcount
- host

`SPL of Interest:`
- eval
- table
- transaction `Workstation maxpause=5m maxevents=-1` 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4776 Status=0xC000006A
| transaction Workstation
| table Workstation TargetUserName eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4776 Status=0xC000006A
| transaction Workstation maxpause=5m maxevents=-1 
| where eventcount > 5 
| eval accounts=mvcount(TargetUserName) 
| where accounts > 2 
| table _time, host, Workstation, TargetUserName, accounts, eventcount 
| sort - _time 
| convert ctime(Time)
```

## BruteForce: Excessive failed password attempts towards one account
`Fields of Interest:`

- `((EventCode=4776 Status=0xC000006A) OR (EventCode=4771 Status=0x18))`
- Status=`0xC000006A` - A logon with misspelled or wrong password.
- TargetUserName 
- Status
- src
- host
- eventcount

`SPL of Interest:`
- eval
- table
- transaction `TargetUserName maxpause=5m maxevents=-1` 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security ((EventCode=4776 Status=0xC000006A) OR (EventCode=4771 Status=0x18)) 
| transaction TargetUserName maxpause=5m maxevents=-1 
| eval sources=mvcount(src) 
| where sources > 1
| table _time host TargetUserName Status src sources eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security ((EventCode=4776 Status=0xC000006A) OR (EventCode=4771 Status=0x18)) 
| eval src=if(src=="::1", Computer, src) 
| transaction TargetUserName maxpause=5m maxevents=-1 
| eval sources=mvcount(src) 
| where eventcount > 5 AND sources > 1 
| table _time, host, TargetUserName, sources, src, eventcount 
| sort - _time
| convert ctime(Time)
```

## BruteForce: Multiple locked accounts from one source
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4740*`
- TargetUserName 
- src
- host
- eventcount

`SPL of Interest:`
- eval
- table
- transaction `TargetDomainName maxpause=1h maxevents=-1` 
- sort

```
source=XmlWinEventLog:Security EventCode =4740
| transaction TargetDomainName
| eval accounts = mvcount (TargetUserName)
| where accounts > 1
| table TargetDomainName, TargetUserName, Computer, eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4740 
| transaction TargetDomainName maxpause=1h maxevents=-1 
| eval accounts=mvcount(TargetUserName) 
| where accounts > 1 
| table _time, host, TargetDomainName, TargetUserName, accounts 
| sort - _time 
| convert ctime(Time)
```
## BruteForce: Logon attempts towards disabled accounts (Kerberos)
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4768*`
- Status=`0x12` - Account is disabled.
- TargetUserName 
- TargetDomainName
- src
- host
- eventcount

`SPL of Interest:`
- eval
- table
- transaction `TargetDomainName maxpause=1h maxevents=-1` 
- sort

```
source=XmlWinEventLog:Security EventCode=4768 Status=0x12
| transaction TargetUserName 
| table TargetUserName TargetDomainName src host eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4768 Status=0x12 
| transaction IpAddress maxpause=5m maxevents=-1 
| where eventcount > 5 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| eval accounts=mvcount(TargetUserName) 
| where accounts > 2 
| table _time, host, Source, TargetUserName, accounts, eventcount 
| sort - _time 
| convert ctime(Time)
```

## Credential Access: Kerberoasting Detection (S02D01)
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4769*`
- Status=`0x1` OR `0x3` OR `0x17` OR `0x18`
- TargetUserName 
- `ServiceName`
- Computer
- src
- host
- eventcount

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index=* EventCode=4769 TicketEncryptionType=0x17
| transaction ServiceName
| table ServiceName TargetUserName Computer src_ip TicketEncryptionType eventcount
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4769 (TicketEncryptionType=0x1 OR TicketEncryptionType=0x3 OR TicketEncryptionType=0x17 OR TicketEncryptionType=0x18) 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| table _time, host, Source, TargetUserName, ServiceName, TicketEncryptionType 
| sort - _time 
| convert ctime(Time)
```
- This search finds sources that requested service tickets with weak cipher suites. 
- These encryption types should be no longer used by modern operating systems in the domain. Therefore, they are likely signs of possible Kerberoasting activity. 
- The search looks at events 4769 auditing service ticket requests. 
- It filters for any ticket requests with encryption type constants equal to the values of vulnerable cipher suites. 
- All requests for tickets with these encryption types are displayed. 
- List of all encryption types can be found at:
  - [4768(S, F): A Kerberos authentication ticket (TGT) was requested: Table 4. Kerberos encryption types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768#table-4-kerberos-encryption-types)

## Credential Access: Excessive service ticket requests from one source (S02D02)
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4769*`
- Status=`0x1` OR `0x3` OR `0x17` OR `0x18`
- TargetUserName 
- ServiceName!= `krbtgt` AND `"\$$"`
- Computer
- src
- host
- eventcount

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4769 ServiceName != krbtgt 
| regex ServiceName != "\$$" 
| transaction IpAddress maxpause=5m maxevents=-1 
| eval services=mvcount(ServiceName) 
| where services > 1 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| table _time, host, Source, TargetUserName, services, ServiceName, TicketEncryptionType 
| sort - _time 
| convert ctime(Time)
```
Requests for several different service names (not related to each other) within a short time period from a single account are suspicious. Even more so if weak encryption was used in the service tickets. This search may help to reveal such activities. 
Service ticket requests for krbtgt service and computer account service names (those ending with $) are filtered out from the results. 
- The search focuses on service accounts that were created for specific services. 
- Subsequent events are grouped on the IpAddress field by the transaction command. 
- Number of services in each transaction is calculated to display only results where the number is higher than the one specified in the condition.

## Credential Access: Suspicious external service ticket requests (S02D03)
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4769*`
- IpPort `0 < IpPort < 1024`
- IpAddress!=`Private IP Address`
- TargetUserName
- ServiceName
- TicketEncryptionType

`SPL of Interest:`
- eval
- table
- transaction 
- sort


```
index=* EventCode=4769 IpPort > 0 (IpPort < 1024 OR (NOT (IpAddress=10.0.0.0/8 OR IpAddress=172.16.0.0/12 OR IpAddress=192.168.0.0/16 OR IpAddress=127.0.0.1 OR IpAddress=::1))) 
| transaction IpAddress
| eval countIpPort=mvcount(IpPort)
| table IpAddress TargetUserName countIpPort ServiceName TicketEncryptionType
```
```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4769 IpPort > 0 (IpPort < 1024 OR (NOT (IpAddress=10.0.0.0/8 OR IpAddress=172.16.0.0/12 OR IpAddress=192.168.0.0/16 OR IpAddress=127.0.0.1 OR IpAddress=::1))) 
| transaction IpAddress
| table _time, host, IpAddress, IpPort, TargetUserName, ServiceName, TicketEncryptionType 
| sort - _time 
| convert ctime(Time)
```
- This search tracks service requests by examining the IP address and port number. 
- Unusual values indicate the use of outbound connection for the service request, which is suspicious. 
- The search examines the IpPort and IpAddress fields in events 4769. 
- Port values under 1024 and any non-private IP addresses are those of interest. 
- The search displays results whenever such values appear in the request, together with details about the requestor.

## Credential Access: Detecting Kerberoasting with a honeypot (S02D04)
`Fields of Interest:`

- sourcetype=`wineventlog`
- EventCode=`*4769*`
- TargetUserName
- ServiceName=`*Honeypot*`
- TicketEncryptionType

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4769 ServiceName=Honeypot01 
| eval Source=if(IpAddress=="::1", Computer, IpAddress) 
| table _time, host, Source, TargetUserName, ServiceName, TicketEncryptionType
| sort - _time 
| convert ctime(Time)
```
- This search uses a detection method for Kerberoasting based on a honeypot. 
- Honeypot is a fake service account that is never really used in the environment, but it is set up to look like a legitimate service account with high privileges assigned. 
- A service ticket requests for this account are only made by an adversary and will be revealed by this search. 
- The search filters all events auditing service requests (4769) for ServiceName equal to the honeypot service account (Honeypot01). 
- The search directly produces results that detect malicious TGS requests.

## Credential Access: Detecting Kerberoasting via PowerShell (S02D05)

```
index="ad_hunting" source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode=4103 OR EventCode=4104) 
| transaction Computer maxpause=15m maxevents=-1 
| eval raw=_raw 
| search [| inputlookup service_accounts.csv 
| eval raw="*" . account . "*" 
| fields raw] 
| where eventcount > 2 
| table _time, Computer, eventcount 
| sort - _time 
| convert ctime(Time)
```

## Credential Access: Possible dump of lsass.exe (Sysmon events) (S03D01)
`Fields of Interest:`

- sourcetype=`xmlwineventlog:microsoft-windows-sysmon/operational`
- EventCode=`8` OR `10`
- host
- SourceImage
- SourceProcessId
- GrantedAccess 

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=8 OR EventCode=10 NOT GrantedAccess=0x1400 NOT GrantedAccess=0x1000 NOT GrantedAccess=0x100000 
| where (TargetImage LIKE "%lsass.exe") 
|search NOT SourceImage="C:\\Windows\\system32\\wininit.exe" NOT SourceImage="C:\\Windows\\system32\\csrss.exe" 
| transaction host, SourceImage, SourceProcessId maxspan=15m 
| table _time, host, SourceImage, SourceProcessId, GrantedAccess 
| sort - _time 
| convert ctime(Time)
```
This search detects possible dump of the LSASS process (lsass.exe) memory via Sysmon events. The process memory contains various credentials while the OS is running.
- To create a dump of the lsass.exe process Administrator or SYSTEM privileges are required, especially SeDebugPrivilege or SeTcbPrivilege.
- These are the primary detection artifacts used in this search. It is essential to focus on processes that accessed lsass.exe with these privileges. 
- The search is focusing on Sysmon events with event codes 10 (ProcessAccess) and 8 (CreateRemoteThread). 
- These events are logged when a process creates another process or thread. The search focuses on processes interacting with lsass.exe with access mask specifying higher privileges. This is achieved by whitelisting the low-privileged access masks. List of access masks can be found at. 
- It is possible to whitelist some processes that commonly access lsass.exe, such as wininit.exe. However, it is strongly recommended to specify the full path to the process, as the name and the location of the executable can be easily changed to look like a legitimate process. The transaction command is used to group accesses of the same process in a short period. Process name and ID are displayed for further investigation.
- [LSASS Memory Read Access](https://threathunterplaybook.com/hunts/windows/170105-LSASSMemoryReadAccess/notebook.html?highlight=lsass%20dump)

## Credential Access: Possible dump of lsass.exe (Windows events) (S03D02)
`Fields of Interest:`

- sourcetype=`XmlWinEventLog:Security`
- EventCode=`4656`
- host
- ProcessName
- ProcessId
- AccessMask

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=4656 NOT AccessMask=0x1400 NOT AccessMask=0x1000 NOT AccessMask=0x100000 
| where (ObjectName LIKE "%lsass.exe") 
| search NOT ProcessName="C:\\Windows\\system32\\lsass.exe" 
| transaction host, ProcessName, ProcessId maxspan=15m 
| table _time, host, ProcessName, ProcessId, AccessMask 
| sort - _time 
| convert ctime(Time)
```
## Credential Access: Creation of a dump file (S03D03)
`Fields of Interest:`

- sourcetype=`xmlwineventlog:microsoft-windows-sysmon/operational`
- EventCode=`11`
- host
- Image
- ProcessId
- TargetFilename

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=11 TargetFilename=*dmp 
| table _time, host, Image, ProcessId, TargetFilename 
| sort - _time 
| convert ctime(Time)
```
- A dump file may be created by using many different tools. Even the Task Manager utility integrated into Windows has this capability. 
- Some programs will create a file with .dmp extension by default or would not allow changing the filename at all. This search hunts for the creation of such files. 
- Sysmon event 11 allows monitoring creation of files together with the process that created them. It is enough to look for a filename ending with dmp and display related information for investigation.
- Dumps created by Task Manager and ProcDump were saved to a file. Both tools assigned the .dmp file extension by default

## Credential Access: Installation of an unsigned driver (S03D04)
`Fields of Interest:`

- sourcetype=`xmlwineventlog:microsoft-windows-sysmon/operational`
- EventCode=`6`
- Signed=`false`
- host
- ImageLoaded
- SHA1
- SignatureStatus

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=6 Signed=false 
| table _time, host, ImageLoaded, Hashes, SignatureStatus 
| sort - _time 
| convert ctime(Time)
```
Some tools used for credential dumping, such as Mimikatz, may attempt to install its own driver to the system. This search aims to detect such attempts by looking at the driver signature. It may also reveal suspicious installations of other drivers to the system beyond the scope of this story. Such events happening on critical systems are surely worth of investigation. 
- The search looks for Sysmon event 6 (Driver loaded) with the value of field Signed equal to false. 
- By this, loading of unsigned drivers on the monitored systems can be spotted. 
- Filename with path and hashes can be then used for investigation. 
Correlation search S03C04 can be used to gain more information.

## Credential Access: Access to GPP honeypot in SYSVOL (S03D05)
`Fields of Interest:`

- sourcetype=`XmlWinEventLog:Security`
- EventCode=`5145`
- RelativeTargetName=`"*test.local\\Policies\\{12345}*"`
- host
- IpAddress
- SubjectUserName
- SubjectUserSid
- SubjectLogonId

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source=XmlWinEventLog:Security EventCode=5145 RelativeTargetName="*test.local\\Policies\\{12345}*" 
| transaction IpAddress, SubjectUserSid maxspan=5m maxevents=-1 
| table _time, host, IpAddress, SubjectUserName, SubjectUserSid, SubjectLogonId 
| sort - _time 
| convert ctime(Time)
```
Group Policy Preferences can be used to distribute passwords across the domain. GPP data is stored in a domain-wide share SYSVOL, to which all Authenticated Users have read access. 
- Therefore, SYSVOL is a common place for attackers to look for credentials. 
- Such attempts can be detected by creating a honeypot (fake group policy with no effective settings) and logging accesses to it. Any access to this file is suspicious, as there are no reasons to access it. 
- Windows event 5145 (A network share object was checked to see whether client can be granted desired access) will provide the desired information. 
- The search filters these events to the honeypot policy file (field RelativeTargetName) and displays information about the origin of the action. The transaction command is used to group multiple events from the same source in a short time to a single one.


## Credential Access: Possible credential database dumping - NTDS.dit (S03D06)
`Fields of Interest:`

- sourcetype=`XmlWinEventLog:Security`
- EventCode=`4688`
- NewProcessName=`"*vssadmin.exe"`
- host
- Computer
- ParentProcessName
- NewProcessName
- TargetUserName


```
index="ad_hunting" source="xmlwineventlog:security" EventCode=4688 NewProcessName="*vssadmin.exe"
| table _time host Computer ParentProcessName NewProcessName TargetUserName
```

- NTDS.dit is the Active Directory database file, an obvious choice for attackers. There are many methods on how to gain access to this file. One of them is to create Volume Shadow Copy of a domain controller. 
- It can be done either by a utility vssadmin.exe or using WMI . WMI can be invoked from PowerShell or by wmic.exe. 
- Another method is to used ntdsutil.exe - a utility used to build a new domain controller faster. 
- Attackers may also use reg.exe to dump hives directly from Registry, where the SAM database is located. 
- The rule detects usage of these methods by looking at command line parameters of newly created processes. 
- The search takes events logging creation of new processes: Windows event 4688 (Sysmon event 1 is better) and filter for known binaries that can access NTDS.dit such as vssadmin.exe.

## Credential Access: Possible dumping via DC synchronization (S03D07)
`Fields of Interest:`

- sourcetype=`XmlWinEventLog:Security`
- EventCode=`4662`
- Properties=
  - DS-Replication-Get-Change
    - GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
  - DS-Replication-Get-Changes-All
    - GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
  - DS-Replication-Synchronize
    - GUID: `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2`
- host
- Computer
- SubjectUserName
- AccessMask
- Properties
- session_id

`SPL of Interest:`
- eval
- table
- transaction 
- sort

```
index="ad_hunting" source="xmlwineventlog:security" EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ab-9c07-11d1-f79f-00c04fc2dcd2*" Caller_User_Name=Administrator
| transaction session_id
| table session_id Logon_ID Properties host Computer SubjectUserName AccessMask
```
- Another method for gaining domain credentials is to abuse the Directory Replication Service Remote protocol used by domain controllers for replication of data. 
- Mimikatz includes a feature DCSync,which effectively "impersonates" a domain controller and requests account password data from a real domain controller. 
- This rule may help to hunt it. The search focuses onevent 4662 (An operation was performed on an object). 
- This event contains field Properties, which enables to determine the access rights used.Therefore, the search filters events based on this field to only those related to DC replication. 
- Then, the `Logon ID`/`Session ID` of the user should be taken from the results and correlated with an authentication event 4624 to see further details about the user session. 
- Most importantly, to determine source workstation and IP address of the activity. The identified IP addresses from the correlation should be those of Domain Controllers, otherwise we are dealing with another endpoint/workstation that has been compromised by an attacker and is impersonating a Domain Controller.

## Persistence: Windows Management Instrumentation (WMI) Event Subscription (T1546.003)
`Fields of Interest:`

- sourcetype=`winsysmon`
- EventCode=`19` OR `20` OR `21`
- EventDescription
- Operation
- Computer
- `21` Consumer
- `19` Query
- `20` Destination

```
index=winsysmon EventCode=19 OR EventCode=20 OR EventCode=21 
| table _time, EventCode, EventDescription, Operation, Computer, Consumer, Query, Destination
```
[Sigma - WMI Event Subscription](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/wmi_event/sysmon_wmi_event_subscription.yml)

## Persistence: Boot or Logon Initialization Scripts (T1037)
`Fields of Interest:`

- sourcetype=`winsysmon`
- EventCode=`11` OR `12` OR `13` OR `14`
- TargetObject=`"*UserInitMprLogonScript*"`
- Operation
- Computer
- Details


[https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.yml#L27](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.yml#L27)
```
index=winsysmon ((ParentImage="*\\userinit.exe" NOT (Image="*\\explorer.exe")) NOT ((CommandLine="*\\netlogon.bat" OR CommandLine="*\\UsrLogon.cmd"))) 
| stats values(cmdline) dc(Computer) AS hosts count by ParentImage Image
```
- [https://github.com/Elemental-attack/Elemental/blob/aad0973d0182082003785109aa63eaeb4ac27856/elemental/media/sigma_rules/sysmon_logon_scripts_userinitmprlogonscript.yml#L4](https://github.com/Elemental-attack/Elemental/blob/aad0973d0182082003785109aa63eaeb4ac27856/elemental/media/sigma_rules/sysmon_logon_scripts_userinitmprlogonscript.yml#L4)
- Sysmon Event IDs (related to registry activity) 11, 12, 13 and 14 can be monitored if they had captured any activity towards the key UserInitMprLogonScripts.
```
index=winsysmon ((EventCode="11" OR EventCode="12" OR EventCode="13" OR EventCode="14") AND TargetObject="*UserInitMprLogonScript*") 
| table Computer, EventCode, signature, TargetObject, Details
```
- [Beyond good ol’ Run key, Part 18](https://www.hexacorn.com/blog/2014/11/14/beyond-good-ol-run-key-part-18/)

## Defense Evasion: Hunt for Renamed PowerShell - Masquerading (T1036)
`Fields of Interest:`

- sourcetype=`winsysmon`
- EventCode=`1`
- Description=`"*Windows PowerShell*"`
- Computer
- User
- Image=`"*\\powershell.exe"` OR `"*\\powershell_ise.exe"`
- cmdline
- ParentImage
- Hashes


```
index=winsysmon EventCode=1 AND Description="Windows PowerShell" AND (Image!="*\\powershell.exe" AND Image!="*\\powershell_ise.exe") 
| rex field=Hashes ".*MD5=(?<MD5>[A-F0-9]*)," 
| table _time, Computer, User, Image, cmdline, ParentImage, MD5
```
```
index=winsysmon EventCode=1 AND Description="Windows PowerShell" 
| rex field=Hashes ".*MD5=(?<MD5>[A-F0-9]*)," 
| stats dc(Computer) AS Hostname count by Image MD5 Description
| sort -count
```
- [https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/deprecated/windows/proc_creation_win_renamed_powershell.yml#L1](https://github.com/SigmaHQ/sigma/blob/e1a713d264ac072bb76b5c4e5f41315a015d3f41/deprecated/windows/proc_creation_win_renamed_powershell.yml#L1)

## Execution: Hunt for PowerShell Empire
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-PowerShell/Operational`
- EventCode=`4104`
- _time
- Computer
- Sid
- Message

```
index=* EventCode=4104 AND ($psversiontable.psversion.major OR system.management.automation.utils OR system.management.automation.amsiutils) 
| eval MessageDeobfuscated = replace(Message, "[ `'+\"\^]","") 
| search EnableScriptBlockLogging OR enablescriptblockinvocationlogging OR cachedgrouppolicysettings OR ServerCertificateValidationCallback OR expect100continue 
| table _time ComputerName Sid MessageDeobfuscated
```
PowerShell Empire is using PowerShell on victim machines to run malicious activity. Since we have PowerShell logs available to us (Script-Block logging), we can use that to detect any malicious usage. Tom Ueltschi (renowned security researcher) proposed a detection rule that looks for any of the following 3 strings:

- $psversiontable.psversion.major
- system.management.automation.utils
- system.management.automation.amsiutils

Then, perform simple deobfuscation on the captured command and look for the occurrence of any of the following 5 strings:

- EnableScriptBlockLogging
- Enablescriptblockinvocationlogging
- cachedgrouppolicysettings
- ServerCertificateValidationCallback
- expect100continue

## Execution: Hunt for Unmanaged PowerShell
`Fields of Interest:`

- sourcetype=`WinEventLog:Windows PowerShell`
- EventCode=`4104`
- host
- Message=`HostApplication=`
- EventCode

```
index=* hostapplication 
| rex field=Message ".*HostApplication=(?<HostApplication>.*)" 
| search HostApplication!="*powershell*" HostApplication!="*\\sdiagnhost.exe*" 
| stats count by host HostApplication sourcetype EventCode
```
- Unmanaged PowerShell can be detected by looking at the Host Application when PowerShell starts and filtering the "known goods" such as PowerShell.exe

## Execution: Hunt for PowerShell Base64 encoded commands
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`1`
- Computer
- User
- ParentImage
- ParentCommandLine
- Image
- CommandLine=`"* -enc*"` OR `"* -en *"` OR `"* -e *"` OR `"* -ec *"`

```
index=* EventCode=1 
| eval cmdline =replace(cmdline, "-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]", "__encoding") 
| search Image="*\\powershell.exe" (cmdline="* -enc*" OR cmdline="* -en *" OR cmdline="* -e *" OR cmdline="* -ec *") 
| transaction ParentImage
| table _time Computer User ParentImage ParentCommandLine Image CommandLine
```
```
index=* EventCode=1 
| eval cmdline =replace(cmdline, "-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]", "__encoding") 
| search Image="*\\powershell.exe" (cmdline="* -enc*" OR cmdline="* -en *" OR cmdline="* -e *" OR cmdline="* -ec *") 
| table _time Computer User cmdline
```
## Lateral Movement: Remote Services: SMB/Windows Admin Shares (T1021.002)
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`1`
- User
- Computer
- ParentImage=`\\\\127.0.0.1\\ADMIN$\\*.exe`
- Image=`*\\rundll32.exe`

```
index="winsysmon" EventCode=1 ParentImage=\\\\127.0.0.1\\ADMIN$\\*.exe AND Image=*\\rundll32.exe 
| table _time Computer User ParentImage Image
```
- After researching through the provided technique and some of the references, the shares that we are interested in are C$, ADMIN$, and IPC$. 
- Common tools that abuse these shares is some of PSExec's implementations - such as the one in Cobalt Strike. 
- A distinctive characteristic is the connection back to the ADMIN$ share on localhost at 127.0.0.1 to execute a binary file which runs rundll32.exe. 

## Execution: Hunt for Download of Word Documents
```
index="winsysmon" EventCode=15 TargetFilename="*.doc.*" 
| table _time Computer Image TargetFilename MD5
```
## Execution: Hunt for Malicious Word document (T1059)
```
index="winsysmon" EventCode=1 ParentImage=*\\winword.exe 
| table _time Computer User Image ParentImage ParentCommandLine
```

## Persistence: Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`13`
- User
- Computer
- TargetObject
- Details
- Image
- EventDescription

```
index="winsysmon" EventCode=13 "*\\Windows\\CurrentVersion\\Run*" 
| transaction Image
| table Image TargetObject Details
```
```
index="winsysmon" EventCode=13 "*\\Windows\\CurrentVersion\\Run*" 
| rex field=Image ".*\\\\(?<Image_EXE>[^\\\\]*)" 
| rex field=TargetObject ".*\\\\CurrentVersion\\\\(?<TargetObj_PATH>.*)" 
| strcat "Image=\"" Image_EXE "\", TargetObject=\"" TargetObj_PATH "\", Details=\"" Details "\"" Image_TargetObj_Details 
| stats dc(Computer) AS Clients values(Image_TargetObj_Details) count by EventDescription Image_EXE
```
After reviewing the MITRE documentation, our hunt will focus on Sysmon Event ID 13, and focus on activity associated with the registry path "\Windows\CurrentVersion\Run". 

## Persistence: Boot or Logon Autostart Execution: Startup Folder (T1547.001)
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`1`
- User
- Computer
- Image=`"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"`
- CommandLine=`"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"`
- MD5

```
index="winsysmon" EventCode=1 Image="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" OR CommandLine="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" 
| table _time Computer User Image CommandLine MD5
```
## Execution: Hunt for Suspicious VBS scripts
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`1`
- User
- Computer
- ProcessId
- ParentImage
- ParentCommandLine
- Image=`"*\\cscript.exe"` OR `"*\\wscript.exe"`
- CommandLine

```
index="winsysmon" EventCode=1 Image="*\\cscript.exe" OR Image="*\\wscript.exe" 
| rex field=Image ".*\\\\(?<Image_fn>[^\\\\]*)" 
| rex field=ParentImage ".*\\\\(?<ParentImage_fn>[^\\\\]*)" 
| stats count by Computer User ProcessId Image CommandLine ParentImage ParentCommandLine
```

## Reconnaissance: Internal Recon (T1547.001)
`Fields of Interest:`

- sourcetype=`WinEventLog:Microsoft-Windows-Sysmon/Operational`
- EventCode=`1`
- User
- Computer
- ParentImage
- ParentCommandLine
- Image
- CommandLine

```
index="winsysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe 
| transaction ParentImage
| table ParentImage ParentCommandLine Image CommandLine _time Computer User
```
```
index="winsysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe 
| bin _time span=15m 
| stats dc(Image) AS CNT_CMDS values(CommandLine) values(ParentCommandLine) count by _time Computer User 
| where CNT_CMDS > 2
```
[CAR-2013-04-002: Quick execution of a series of suspicious commands](https://car.mitre.org/analytics/CAR-2013-04-002/)


## Reconnaissance: BruteForce Attack
`Field of Interest:`

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
	
`SPL of Interest:`
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
`Field of Interest:`
- source: `stream:http`
- http_user_agent 
- http_content_type

`SPL of Interest:`
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
`Field of Interest:`

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
	
`SPL of Interest:`
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
`Field of Interest:`

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
	
`SPL of Interest:`
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
`Fields of Interest:`

- EventCode: `*104*` or `*1102*`
- RecordNumber
- Account_Name
- New_Process_Name
- Process_Command_Line

	
`SPL of Interest:`
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

`Fields of Interest:`

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
`Fields of Interest:`

- sourcetype= `wineventlog` or `sysmon`
- event.code: `*1*` OR `*4624*`
- host
- dest
- Security_ID 
- Logon_ID
- Parent_Process
- Image
- CommandLine

`SPL of Interest:`
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
`Fields of Interest:`

- sourcetype= `wineventlog` or `sysmon`
- event.code: `*1*` OR `*4624*`
- TaskCategory 
- Account_Name
- Security_ID
- ParentCommandLine
- CommandLine

`SPL of Interest:`
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
`Fields of Interest:`

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
`Fields of Interest:`

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

## Persistence: Create Account
`Fields of Interest:`

Process
- EventCode: `*4720* `
- Account_Name: `Requestor`
- SAM_Account_Name: `Created Account`
- ComputerName
- Logon_ID
- host 

`Event IDs specific to account logon events`
- 4624 (successful logon) 
- 4625 (failed logon) 
- 4634 (successful logoff) 
- 4647 (user-initiated logoff) 
- 4648 (logon using explicit credentials) 
- 4672 (special privileges assigned) 
- 4768 (Kerberos ticket (TGT) requested) 
- 4769 (Kerberos service ticket requested) 
- 4771 (Kerberos pre-auth failed) 
- 4776 (attempted to validate credentials) 
- 4778 (session reconnected) 
- 4779 (session disconnected)

`SPL of Interest:`
- transpose
- table
- rex

```
index="botsv2" sourcetype=wineventlog EventCode=4720
```
**Pivot Newly Created Account**
```
index="botsv2" sourcetype=wineventlog EventCode=4720
| table _time host Account_Name SAM_Account_Name
```
**Account Comparison**
```
index=botsv2 sourcetype=wineventlog EventCode=4720 svcvnc
| table _time host Account_Name SAM_Account_Name Display_Name User_Principal_Name Home_Directory Home_Drive Script_Path Profile_Path User_Workstations Password_Last_Set Account_Expires Logon_Hours
| transpose
```
**Pivoting other EventCode**
```
index=botsv2 sourcetype=wineventlog (host=wrk-klagerf OR host=wrk-btun) EventCode!=4688 svcvnc
| eval current_account=mvindex(Security_ID,0)
| eval account_modified=mvindex(Security_ID,1)
| rex field=Message "(?<short_message>.*\r)"
| table _time host EventCode current_account account_modified Security_ID short_message
| sort _time
```
**Pivoting Logon Using Explicit Credentials**
```
index=botsv2 sourcetype=wineventlog EventCode=4648 service3
| eval current_account=mvindex(Security_ID,0)
| eval account_modified=mvindex(Security_ID,1)
| rex field=Message "(?<short_message>.*\r)"
| table _time host EventCode current_account account_modified Security_ID short_message
| sort _time
```

## Command and Control: Outbound Connection with Suspicious File Retrieval
`Field of Interest:`

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
	
`SPL of Interest:`
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
`Field of Interest:`

- source: `stream:http` or `stream:http`
- c_ip
- src_ip
- src_ip: `External IP`
- dest_port
- dest_ip: `Internal IP` 
- http_method: `POST`
- method
- `filename=`
	
`SPL of Interest:`
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
`Field of Interest:`

- source: `suricata`
- src_ip
- src_port 
- dest_ip
- dest_port
- method_parameter
- method
- reply_content
	
`SPL of Interest:`
- rex
- stats

```
sourcetype=suricata AND cerber
| stats count by alert.signature_id
```

`Field of Interest:`

- source: `pan.traffic`
- src_ip
- src_port
- dest_ip: 
- dest_port
- user

`SPL of Interest:`
- rex
- stats
- eval
- timechart

**Firewall Investigation and Pivoting Usernames**
```
index=botsv2 sourcetype="pan:traffic" dest=45.77.65.211
| eval uniq=src_ip." ".user 
| timechart sum(bytes) as bytes by uniq
```

## Command and Control: Suspicious Traffic (DNS)
`Field of Interest:`

- source: `suricata`
- src_ip
- src_ip: 
- dest_port
- dest_ip:  
- record_type
- query
- bytes
	
`SPL of Interest:`
- transaction
- stats

```
sourcetype="stream:dns" src_ip="192.168.250.100" record_type=A
| transaction src_ip
| table src_ip, dest_ip, query{}
```

## Execution: Malicious Scripting
`Field of Interest:`

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

`SPL of Interest:`
- transaction
- eval

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 *vbs* *js* *jse*
| transaction ParentImage
| eval lenCMD = len(CommandLine)
| table ParentImage, ParentCommandLine, Image, CommandLine, lenCMD
```

## Execution: Malicious Process Execution
`Field of Interest:`

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

`SPL of Interest:`
- transaction
- eval

**Sort by Parent CommandLine and Image**
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="venus" user=*service3*
| transaction ParentImage
| table ParentImage, ParentCommandLine, Image, CommandLine
```
**Sort by initial execution of Parent CommandLine and Image**
```
*ARTIFACT* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine=*
| table _time, CommandLine, ProcessId, ParentCommandLine, ParentProcessId 
| reverse
```
```
index=botsv2 *hostname* schtasks.exe
```
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *hostname* *suspicious_tools*
```
**Base64 Powershell**
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  ParentCommandLine=* WwBSAGUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAFQAVABZAHAA*
|  stats count by host
AND
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  ParentCommandLine=* WwBSAGUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAFQAVABZAHAA*
|  table _time host user CommandLine
|  sort-_time
|  reverse
OR
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  ParentCommandLine=* WwBSAGUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAFQAVABZAHAA*
|  transaction host
|  table _time host user CommandLine
|  sort-_time
|  reverse
```
**Correlate Commandlinec with same ParentCommandLine**
```
index="botsv2" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  ParentCommandLine=*powershell*-enc* (host=wrk-btun OR host=mercury) 
| stats values(CommandLine) as CommandLine by ParentCommandLine 
| fields - ParentCommandLine
```
**Correlate Powershell Execution**
```
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" (CommandLine=*powershell*-enc* OR ParentCommandLine=*powershell*-enc*)
| eval shortCL=substr(CommandLine,1,90)
| eval shortPCL=substr(ParentCommandLine,1,80)
| transaction ParentImage
| table _time host user ParentImage shortPCL ParentProcessId ProcessId shortCL
| sort + _time
```
**Correlate PID and PPID**
```
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" (CommandLine=*powershell*-enc* OR ParentCommandLine=*powershell*-enc*) (host=wrk-btun OR host=mercury) 
| stats count by ParentProcessId ProcessId
```


## Initial Access: USB 
`Field of Interest:`

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
`Field of Interest:`

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

`SPL of Interest:`
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
`Field of Interest:`

sourcetype: `suratica`
- ssl_subject_common_name
- tls.fingerprint
- tls.issuerdn
- src_ip
- dest_ip


`SPL of Interest:`
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
`Field of Interest:`

sourcetype: `stream:smb`
- dest_ip
- src_ip
- bytes
- filename
- command
- flowid

`SPL of Interest:`
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
`Field of Interest:`

sourcetype: `stream:ftp`
- dest_ip
- src_ip
- method
- reply_code
- reply_content
- filename
- loadway: `Upload` or `Download`
f


`SPL of Interest:`
- transaction
- table

**Check for Notable NetFlow**
```
index="botsv2" ftp
| stats count by sourcetype
| sort - count
```
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
**Time Series Data**
```
index="botsv2" ftp sourcetype="pan:*"  src=* dest=*
| eval uniq=src." ".dest
| timechart count by uniq
OR
index="botsv2" ftp sourcetype="suricata"  src=* dest=*
| eval uniq=src." ".dest
| timechart count by uniq
OR
index="botsv2" ftp sourcetype="stream:ftp"   src=* dest=*
| eval uniq=src." ".dest
| timechart count by uniq
```
**FTP ctivities**
```
index="botsv2" ftp sourcetype="stream:ftp"
| transaction dest_ip
| table _time dest_ip src_ip method method_parameter reply_content 
| sort - _time
| reverse
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

`Field of Interest:`

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

`SPL of Interest:`
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
`Field of Interest:`

sourcetype: `stream:ftp`
- dest_ip
- src_ip
- hostname
- query
- bytes_in
- bytes_out

`SPL of Interest:`
- transaction
- table
- stats

```
index="botsv2" sourcetype="stream:dns" 160.153.91.7
| table _time name src src_dns dest
```
```
index="botsv2" sourcetype="stream:dns" hildegardsfarm.com
| timechart span=1s count by dest_ip
```
**Sort by Destination**
```
index="botsv2" sourcetype="stream:dns" hildegardsfarm.com 
| transaction dest_ip
| table dest_ip, src_ip, hostname{}, query{}, bytes_in, bytes_out
```
**Filter DNS QUERY**
```
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY
| table _time query src dest
OR 
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY
| transaction src | dedup src, dest
| eval total_query=mvcount(query) 
| table src dest total_query
```
**URL TOOLBOX**
```
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY query=*.hildegardsfarm.com
| eval query=mvdedup(query)
| eval list="mozilla"
| `ut_parse_extended(query,list)`
| `ut_shannon(ut_subdomain)`
| table src dest query ut_subdomain ut_shannon
```
**Average Length of the Subdomain**
```
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY query=*.hildegardsfarm.com
| eval query=mvdedup(query)
| eval list="mozilla"
| `ut_parse_extended(query,list)`
| `ut_shannon(ut_subdomain)`
| eval sublen = length(ut_subdomain)
| table ut_domain ut_subdomain ut_shannon sublen
| stats count avg(ut_shannon) as avg_entropy avg(sublen) as avg_sublen stdev(sublen) as stdev_sublen by ut_domain
```
**DNS Exfiltration Visualization**
```
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY query=*.hildegardsfarm.com
| eval query=mvdedup(query)
| eval list="mozilla"
| `ut_parse_extended(query,list)`
| `ut_shannon(ut_subdomain)`
| eval sublen = length(ut_subdomain)
| stats count avg(ut_shannon) as avg_entropy avg(sublen) as avg_sublen stdev(sublen) as stdev_sublen by ut_domain src dest
| sort - count
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
## Execution: Rundll32
`Fields of Interest:`

- process.name: `rundll32.exe`
- process.args:`*pcwutl.dll*` `*LaunchApplication*`
- process.args:`("*\\rundll32.exe* url.dll,*OpenURL *" "*\\rundll32.exe* url.dll,*OpenURLA *" "*\\rundll32.exe* url.dll,*FileProtocolHandler *" "*\\rundll32.exe* zipfldr.dll,*RouteTheCall *" "*\\rundll32.exe* Shell32.dll,*Control_RunDLL *" "*\\rundll32.exe javascript\:*" "* url.dll,*OpenURL *" "* url.dll,*OpenURLA *" "* url.dll,*FileProtocolHandler *" "* zipfldr.dll,*RouteTheCall *" "* Shell32.dll,*Control_RunDLL *" "* javascript\:*" "*.RegisterXLL*")`

Reference:
- [win_susp_rundll32_activity.yml](https://gist.github.com/curi0usJack/14d1b2062691c0a50c4dae6f29001107)

## Execution: URL.dll/IEFrame.dll
`Fields of Interest:`

- event.code: `*1*` 
- winlog.event_data.ParentImage
- process.name: `rundll32.exe`
- process.args:`(url.dll OR ieframe.dll)` AND `(FileProtocolHandler OR OpenURLA)`

## Execution: Pcwutl
`Fields of Interest:`

- event.code: `*1*` 
- winlog.event_data.ParentImage
- process.name: `rundll32.exe`
- process.args:`*pcwutl.dll*` `*LaunchApplication*`

Reference:
- [LOLBIN - Pcwutl.dll](https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/)

## Execution: Squiblydoo
`Fields of Interest:`

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
`Fields of Interest:`

- event.code: `*1*` or `*4688*`
- process.parent.executable : `*winword.exe*`
- process.executable : `*powershell.exe* OR *cmd.exe*`
- Time
- winlog.computer_name
- winlog.user.name
- agent.hostname / host.name

## Persistence: Short Time Scheduled Tasks
`Fields of Interest:`

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
`Fields of Interest:`

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

`Fields of Interest:`

- event.code: `*3*` OR `*59*` OR `*60*`
- channel
- event.action: `*BITS*`
- bytesTransferred
- url
- message

## Privelege Escalation: UAC Bypass Using SDCLT.EXE
`Fields of Interest:`

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
`Fields of Interest:`

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

`Fields of Interest:`

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
``Fields of Interest:``

- event.code: `*104*` or `*1102*`
- Time
- winlog.computer_name
- winlog.channel
- agent.hostname / host.name
- user.name


## Defense Evasion: RDP Settings Tampering
``Fields of Interest:``

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

``Fields of Interest:``

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
`Fields of Interest:`

- event.code: `*1*` or `*4688*`
- Time 
- process.parent.executable 
- process.executable
- process.parent.command_line: `*.dmp*` `*lssas*`
- process.command_line 
- agent.hostname / host.name
- winlog.user.name

## Credential Access: Credential Dumping thru Fileless Attack
`Fields of Interest:`

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

`Fields of Interest:`

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

`Fields of Interest:`

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

`Fields of Interest:`

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

`Fields of Interest:`

- event.code: `*1*` 
- process.parent.executable : `*wmiprvse.exe*`
- process.executable : `*powershell.exe* OR *cmd.exe*`
- Time
- winlog.computer_name
- winlog.user.name
- agent.hostname / host.name


## Lateral Movement: Possible Remote WMI Abuse - Mimikatz (Remote Login)
`Fields of Interest:`

A logon was attempted using explicit credentials (Windows Security)
- event.code: `*4648*`
- Account.Name
- Account.Domain
- process.executable: `*C:\Windows\System32\svchost.exe*`
- process.executable: `*C:\Windows\System32\wbem\WMIC.exe*`

[Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-Mimikatz.htm)

## Impact: Inhibit System Recovery - Vssadmin 
`Fields of Interest:`

- event.code: `*1*` or `*4688*`
- Time
- process.working_directory 
- process.parent.executable: `*cmd*`
- process.executable: `*vssadmin*`
- process.command_line: `*vssadmin*` `*delete*` `*shadows*` 
- agent.hostname / host.name

## Credential Attack
`Fields of Interest:`

- event.code: `*4625*`
- Time
- agent.name / winlog.computer_name
- user.name
- winlog.event_data.LogonType
- winlog.event_data.FailureReason
- winlog.logon.failure.reason
- winlog.logon.failure.sub_status

## Remote Login Sessions
`Fields of Interest:`

- event.code: `*4624* (Logon Successful)`
- event.code: `*4625* (Failed Logon)`
- winlog.event_data.LogonType: `*10*`
- Time
- agent.name / winlog.computer_name
- user.name
- winlog.logon.type

## Network Monitoring IP
`Fields of Interest:`

- event.code: `*3*`
- Time	
- agent.name	
- agent.hostname / host.name
- winlog.computer_name	
- process.executable	
- user.name	
- destination.domain

## Network Monitoring Domain
`Fields of Interest:`

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
`Fields of Interest:`

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


# Bro-ZEEK - Intel-driven Threat Hunting
- [Hunting for APT in network logs (PPT)](https://www.slideshare.net/OlehLevytskyi1/hunting-for-apt-in-network-logs-workshop-presentation)
- [Hunting for APT in network logs - Oleh Levytskyi, Bogdan Vennyk](https://www.youtube.com/watch?v=PmwFpwTCy88&t=5979s)

## Initial Access: RDP Bruteforce
`Field of Interest:`
- sourcetype=`bro:rdp:json`
- cookie
- id.orig_h
- id.orig_p=`Incrementing Port`
- id.resp_h
- id.resp_p=`3389`

```
index="rdp_bruteforce" sourcetype="bro:rdp:json" id.resp_p=3389
| transaction cookie
| eval total_srcp=mvcount(src_port)
| table cookie, id.orig_h, total_srcp, id.resp_h, id.resp_p
```

## Initial Access: SSH Bruteforce
`Field of Interest:`
- sourcetype=`bro:ssh:json`
- id.orig_h
- id.orig_p=`Incrementing Port`
- id.resp_h
- id.resp_p=`3389`
- server
- client

```
index="ssh_bruteforce" sourcetype="bro:ssh:json" id.resp_p=22
| transaction id.orig_h
| eval total_srcp=mvcount(src_port)
| table id.orig_h, total_srcp, id.resp_h, id.resp_p, server, client
```

## Initial Access: Beaconing
`Field of Interest:`
- sourcetype=`bro:http:json`
- id.orig_h
- id.orig_p
- id.resp_h
- id.resp_p
- user_agent

uri_path=
- `/ca`
- `/dpixel`
- `/__utm.gif`
- `/pixel.gif`
- `/g.pixel`
- `/dot.gif`
- `/updates.rss`
- `/fwlink`
- `/cm`
- `/cx`
- `/pixel`
- `/match`
- `/visit.js`
- `/load	  `
- `/push`
- `/ptj`
- `/j.ad`
- `/ga.js`
- `/en_US/all.js`
- `/activity`
- `/IE9CompatViewList.xml`

**Beaconing Detection**
```
index="cobaltstrike_beacon" sourcetype="bro:http:json" 192.168.151.181
| transaction user_agent
| table uri_path, user_agent, src_ip, dest_ip
```
**Beacon - URI Path**
```
index=* (uri_path=*/ca* OR */dpixel* OR */__utm.gif* OR */pixel.gif* OR */g.pixel* OR */dot.gif* OR */updates.rss* OR */fwlink* OR */cm* OR */cx* OR */pixel* OR */match* OR */visit.js* OR */load* OR */push* OR */ptj* OR */j.ad* OR */ga.js* OR */en_US/all.js* OR */activity* OR */IE9CompatViewList.xml* OR */submit.php*)
| dedup uri_path
| transaction dest_ip
| table dest_ip, src_ip, uri_path, user_agent
```
**Beaconing - Time Interval**
```
index="cobaltstrike_beacon" sourcetype="bro:http:json" dest=192.168.151.181 src=10.0.10.20
| timechart count
OR
index="cobaltstrike_beacon" sourcetype="bro:http:json" dest=192.168.151.181 src=10.0.10.20
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| convert ctime(prevtime)
| stats count by _time, prevtime, timedelta
```
**Beaconing - Response Byte**
```
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest=192.168.151.181 src=10.0.10.100
| stats count by _time, resp_bytes
| fields - count
OR
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest=192.168.151.181 src=10.0.10.100
| stats count by _time, resp_bytes, src_ip, dest_ip
| transaction resp_bytes
| fields - count
```

Reference:
- [Cobalt Strike Analysis and Tutorial: How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)

## Reconnaissance: Network Scanning
`Field of Interest:`
- source=`*conn.log`
- dest_port
- dest_ip
- src_ip
- _time

**General Checking of Destiantion Port**
```
source=*conn.log
| transaction dest_port, dest_ip
| dedup dest_port, dest_ip
| table dest_port, dest_ip, src_ip, _time
```
**Basic Scanning**
```
source=*conn.log
| bin span=5m _time
| transaction dest_ip, src_ip
| eval total_dsrprt=mvcount(dest_port)
| where total_dsrprt >= 1000
| table total_dsrprt, dest_ip, src_ip
```
```
source=*conn.log
| bin span=5m _time
| stats dc(dest_port) as num_dest_port, values(dest_ip) as dest_ip by _time, src_ip
| where num_dest_port >= 1000
```
NMAP scan was successfully detected, but there are couple things which should be taken into
consideration:
- Threshold for unique destination ports is more or equal than 1000. From our observations, when
adversaries get initial access, they hunt for specific ports like SMB or RDP, up to 10 ports at a time.
- Other IPs were marked as scanned, beside the one scanned by NMAP.

**Successful Scanning of OpenPort**
```
source=*conn.log
| bin span=5m _time
| transaction dest_ip, src_ip
| eval total_dsrprt=mvcount(dest_port)
| where total_dsrprt >= 1000
| table total_dsrprt, dest_ip, src_ip
```
```
source=*conn.log orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0./12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 1000
```

During port scanning NMAP is trying to establish TCP handshake on each port and if it is successful it means the port is open. Also remote service can return its banner, so in that case NMAP will get some data back, but the amount of data NMAP sends to the scanning port is always the same and it's zero (beside TCP handshake itself). Unless we care about external connections they can be excluded to reduce false-positive rate.

## Reconnaissance: DCE/RRC SMB Share Enumeration
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- id.orig_h
- id.resp_h
- id.resp_p=`445`
- endpoint
- operation
- _time


```
sourcetype="bro:dce_rpc:json" 
| transaction endpoint
| table _time, id.orig_h, , id.resp_h, id.resp_p, endpoint, operation
```
```
sourcetype="bro:dce_rpc:json" operation=NetrShareEnum endpoint=srvsvc
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
`operation=NetrShareEnum`: This filter narrows down the events to those where the operation field equals `NetrShareEnum`. The `NetrShareEnum` operation is part of the Server Service (often referred to as srvsvc), which can be used to retrieve a list of shared resources on a system. Monitoring this operation is crucial because attackers could use it to gain information about network shares as a part of reconnaissance activities.

## Credential Access: Kerberos Bruteforce Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- error_msg
- id.orig_h
- id.resp_h
- request_type=`AS`
- _time

**Kerberos Bruteforce Detection**
```
sourcetype="bro:kerberos:json"
success="false" request_type=AS
| stats count as attempts, dc(client) as total_clients, values(error_msg) as error_messages by id.orig_h, id.resp_h
| table id.orig_h, id.resp_h, attempts, total_clients, error_messages
| where attempts>30
```
```
sourcetype="bro:kerberos:json" 
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Client" values(error_msg) by _time, id.orig_h, id.resp_h
| where count>30
```

Kerberos requests
- AS-REQ = User presents password, gets TGT
- TGS-REQ = User presents TGT, gets Service Ticket

No. Abbreviation Function
- 10 AS-REQ Request Ticket-Granting Ticket
- 11 AS-REP Ticket-Granting Ticket
- 12 TGS-REQ Request Service Ticket
- 13 TGS-REP Service Ticket
- 30 KRB-ERROR error

[MIT Kerberos Documentation - Encryption types](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html#:~:text=Kerberos%20can%20use%20a%20variety,confidentiality%20and%20integrity%20to%20data.)


## Credential Access: Kerberoasting Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- service
- id.orig_h
- id.resp_h
- request_type=`TGS`
- cipher=`"rc4-hmac"`
- forwardable=`"true"`
- renewable=`"true"`
- _time

```
sourcetype="bro:kerberos:json" request_type=TGS cipher="rc4-hmac" forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```
This query is valuable for security monitoring and auditing within environments that use Kerberos for authentication. 
- `cipher="rc4-hmac"`: This is significant because while RC4-HMAC was once common, it is now considered less secure than newer encryption types like AES. Monitoring its usage can help identify older or potentially insecure configurations.
- `forwardable="true"`: Forwardable tickets allow the client (or an intermediary on behalf of the client) to request additional TGS tickets to different services on behalf of the user, increasing flexibility but also potentially increasing security risk if misused.
- `renewable="true"`: Renewable tickets can be renewed without the client needing to re-authenticate using their password, which is useful for long-running jobs or services.


## Credential Access: Kerberoasting Detection
`Field of Interest:`
- sourcetype=`bro:kerberos:json` or `kerberos.log`
- client
- id.orig_h
- id.resp_h
- request_type=`TGS`
- _time

```
sourcetype="bro:kerberos:json"
| where client!="_"
| bin _time span=1m
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```
Potential Golden Ticket attacks by focusing on unusual TGS request patterns within Kerberos logs
[detect_kerberos_attacks.sh](https://github.com/exp0se/detect_kerberos_attacks/blob/master/detect_kerberos_attacks.sh)

## Credential Access: DCSync Attack Detection
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- endpoint
- operation
- id.orig_h
- id.resp_h
- operation=`DRSGetNCChanges`
- _time

```
sourcetype="bro:dce_rpc:json" operation=DRSGetNCChanges
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
Extract and analyze logs related to a specific DCE/RPC operation, specifically `DRSGetNCChanges`, which is crucial in Active Directory environments for replication of directory changes.

`operation=DRSGetNCChanges`: This filter restricts the logs to those where the operation field is set to `DRSGetNCChanges`. This operation is significant in the context of Windows Server Active Directory as it is used by domain controllers to replicate directory objects and changes. In security monitoring, watching this operation is critical because unauthorized or malicious replication requests can indicate attempts at creating backdoors or extracting sensitive directory information.

## Lateral Movement
Lateral movement attacks
Exploitation of Remote Services
- Zerologon
- Print Nightmare

Remote Services
- RDP
- SMB
- DCOM
- SSH
- VNC
- WinRM

Use Alternate Authentication Material
- Pass-the-hash
- Pass-the-ticket

## Lateral Movement: PSExec CobaltStrike Execution Detection
`Field of Interest:`
- sourcetype=`bro:smb_files:json` or `smb_files.log`
- name=`"*.exe"`, `"*.dll"`, `"*.bat"`
- path=`"*\\c$"`, `"*\\ADMIN$"`
- id.orig_h
- id.resp_h
- _time


```
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```
```
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
| transaction name
| table name, path, action id.orig_h,  id.resp_h, id.resp_p
```
Check for SMB (Server Message Block) file access events, specifically focusing on potentially sensitive or executable file types within high-risk administrative shares

## Lateral Movement: Fileless PSExec Execution (SharpNoPSExec) using Service Creation
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`"CreateServiceW"`, `"CreateServiceA"`, `"StartServicew"`, `"StartServiceA"`,
`"ChangeServiceConfigW"`
- endpoint
- operation
- id.orig_h
- id.resp_h
- _time

```
sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServicew", "StartServiceA",
"ChangeServiceConfigW")
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServicew", "StartServiceA",
"ChangeServiceConfigW")
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
Analyze and monitor specific DCE/RPC activities related to service control operations in Windows environments
- Unauthorized or malicious service creation or modification, which could be part of an attacker's efforts to establish persistence or escalate privileges on a system.
- Start of services that may be unusual or unauthorized, potentially indicating that an attacker is activating malicious services designed to perform harmful actions.

[SharpNoPSExec - File less command execution for lateral movement](https://github.com/juliourena/SharpNoPSExec/blob/master/SharpNoPSExec/Program.cs)

## Lateral Movement: Possible ZeroLogon Activity Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`"NetrServerReqChallenge"` OR `"NetrServerAuthenticate3"` OR `"NetrServerPasswordSet2"`
- endpoint
- id.orig_h
- id.resp_h
- _time

```
endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| transaction endpoint
| table endpoint, operation _time, id.orig_h, id.resp_h
```
```
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

Firstly, the vulnerability is exploited by sending specially crafted `NetrServerReqChallenge`, `NetrServerAuthenticate3` and `NetrServerPasswordSet2` DCERPC requests to initially bind to and use the NETLOGON interface. This is followed by sending specific Opnum like 2, 26 and 30 to set the domain controller password to NULL. Filters the events to only include those related to three specific Netlogon operations:
- `NetrServerReqChallenge`: Part of the authentication sequence where the server challenges the client to prove its identity.
- `NetrServerAuthenticate3`: Used for establishing a secure channel and authenticating clients and servers in the domain.
- `NetrServerPasswordSet2`: Used to change the machine account password, which if done maliciously, can disrupt domain communications or facilitate unauthorized access.

[Network Threat Hunting for Zerologon Exploits (CVE-2020-1472)](https://arista.my.site.com/AristaCommunity/s/article/Network-Threat-Hunting-for-Zerologon-Exploits-CVE-2020-1472)

## Lateral Movement: Print Spooler Activity Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time

```
sourcetype="bro:dce_rpc:json" operation=RpcAddPrinterDriverEx OR operation=RpcEnumPrinterDrivers
| transaction endpoint
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
index="printnightmare" endpoint=spoolss operation=RpcAddPrinterDriverEx OR operation=RpcEnumPrinterDrivers
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

Heuristics are simple check for PrintNightmare:
- \pipe\spoolss in named_pipe
- spoolss in endpoint
- RpcEnumPrinterDrivers OR RpcAddPrinterDriverEx in operation

Reference:
- [Simple policy to detect CVE-2021-1675](https://github.com/initconf/cve-2021-1675-printnightmare)
- [PrintNightmare (CVE-2021-1675)](https://community.netwitness.com/t5/netwitness-community-blog/printnightmare-cve-2021-1675/ba-p/625335)


## Lateral Movement: DCOM Execution Detection 
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time


```
sourcetype="bro:dce_rpc:json" endpoint=IDispatch 
| table _time, id.orig_h, id.resp_h, endpoint, operation
```
```
sourcetype="*bro:dce_rpc:json*" endpoint=IDispatch
| transaction id.orig_h
| table operation, id.orig_h, id.resp_h, endpoint, _time
```

- `endpoint=IDispatch`: This filter targets log entries where the endpoint involved is IDispatch. IDispatch is a part of the Component Object Model (COM) in Microsoft Windows, which enables an application to call functions of objects implemented in other applications or (often) remote processes. The use of `IDispatch` can be particularly interesting from a security perspective because it could be used in methods involving automation, remote procedure calls, or interacting with processes across different security contexts.

[LATERAL MOVEMENT VIA DCOM: ROUND 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

## Exfiltration: CobaltStrike Data Exfiltration
`Field of Interest:`
- sourcetype=`bro:dce_rpc:json` or `dce_rpc.log`
- operation=`RpcAddPrinterDriverEx`
- endpoint
- id.orig_h
- id.resp_h
- _time


Cobalt Strike data exfiltration detection steps
1. Filter out check-in beacon data
2. In case of HTTP beacons, they are using GET requests, so we can just look for POST requests
payload data (packet content without HTTP header).
3. In case of HTTPS beaconing you need to find this value statistically and filter it out manually.

**CobaltStrike data exfiltration using HTTP Beacon**
```
sourcetype="bro:http:json" method=POST dest_ip=192.168.151.181
| stats sum(request_body_len) as TB by src, dest, dest_port
| eval TB = TB/1024/1024
```
Converts the total bytes into megabytes for easier interpretation

**CobaltStrike HTTPS - Find Beacon**
```
index="cobaltstrike_exfiltration_https"sourcetype="bro:conn:json"
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval percent = (count/total)*100
| where percent > 70 AND total > 50
| table percent, total, src, dest, dest_port, dest_port, resp_bytesB by src, dest, dest_port
```
OR
```
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json"
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval percent = (count/total)*100
| where percent > 70 AND total > 50
| table percent, total, src, dest, dest_port, dest_port, resp_bytes
```
**CobaltStrike HTTPS - Filter-out Beacon**
```
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json" resp_bytes!=316 dest=192.168.151.181 dest_port=443
| stats sum(orig_bytes) as TB by src, dest, dest_port
| eval TB = TB/1024/1024
```

## Exfiltration: CobaltStrike Data Exfiltration - Data Transfer Size Limit
```
index="exfiltration_data_size_limits" sourcetype="bro:conn:json"
| bin span=1m time
| rename id.origin_host as src_ip, id.resp_host as dest_ip, id.resp_p as dest_port, orig_ip_bytes as bytes_out
| stats count by _time, bytes_out
```

## Exfiltration: DNS Exfiltration
`Field of Interest:`
- sourcetype=`bro:dns:json` or `dns.log`
- query
- id.orig_h
- id.resp_h
- _time

**Timechart DNS**
```
sourcetype="bro:dns:json" blue.letsgohunt.online
| timechart span=1s count by dest_ip
```
**Average Length of the Subdomain**
```
sourcetype="bro:dns:json" "blue.letsgohunt.online"
| eval query=mvdedup(query)
| rex field=query "(?<ut_identifier>(?:\w+\.)+)(?<ut_subdomain>[^\.]+[^\.]+)\.(?<ut_domain>[^\.]+\.[^\.]+)$"
| eval sublen = len(ut_identifier)
| table ut_identifier ut_subdomain ut_domain sublen
```
**Unusual Long Subdomain**
```
sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="* amazonaws.com *" AND query!="*._google cast.*" AND query!="_ldap.*"
| stats count(query) as req_by_day by id.orig_h, id.resp_h
| sort - req_by_day
```
```
sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="* amazonaws.com *" AND query!="*._google cast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
```

## Impact: Encryption - **Ransomware behavior 1**
- Start
- Enumerate files
- Read file(read file content) - `SMB:: FILE_OPEN`
- Encrypt file (encryption in memory)
- Write file (Write encrypted data to a file) - `SMB: FILE_RENAME`
- The same file

```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```


## Impact: Encryption - **Ransomware behavior 2**
- Start
- Enumerate files
- Read file (read file content)
- Delete original file
- Encrypt file (encryption in memory)
- Write new file (Write encrypted data to a file)

```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
```

## Impact: Encryption - **Ransomware behavior 3**

Ransomware behavior 3
- Start
- Enumerate files
- Read file (read file content) `SMB::FILE_OPEN`
- Encrypt file (encryption in memory)
- Write file with specific extension (Write encrypted data) `SMB::FILE_RENAME`

```
sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort - count
```
**Check for Unique FileExtension**
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_RENAME")
| eval base_length = len(prev_name)
| eval new_extension = substr(name, base_length + 1)
| where isnotnull(new_extension) AND new_extension != ""
| stats count by new_extension, src_ip, dest_ip
| sort - count
| table new_extension, count, src_ip, dest_ip
```
```
sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| rex field=name "^(?<base_file>.*?)(?:\.(?<extension>[^\.]+))?$"
| stats values(base_file) as filenames by extension, src_ip, dest_ip
| sort - count(filenames)
| table extension, filenames, src_ip, dest_ip
```