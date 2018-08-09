# TheHive2Sigma

## What is?

**TheHive2Sigma** is a python script that through the API of [The Hive](http://thehive-project.org/), gets all observables related to an specific case and creates a [Sigma Rule](http://github.com/Neo23x0/sigma) to search in your Siem solution to know how many logs matches your observables.

At this moment, TheHive2Sigma is able to create Sigma rules for the following type of observables:

* **Ip address**
* **Fqdn**
* **Domain**
* **Registry keys**
* **Process** (since there is no process observable type on The Hive by default, create one under Admin --> Observables)


## How it works?

Install python libraries:

```
pip install -r requirements.txt
```

Open with your favourite text editor the file and fulfill the three empty variables written on the begining of the script:


```
#Config
thehive_url = 'https://thehive.bussiness.com:9000' # The hive URL including port
thehive_api = 'oczZpMn44t6bgImffz7Odfred87sEA7u' #Api key for The Hive
thehive_case = 'ADAS3pWuOTfe0bZni0kV' # The Hive case id (20 chars)
```

Simply run the script and it will print out a Sigma Rule:
```
python thehive2sigma.py
```


Sample output:

```
action: global 
title: Case 5 WannaFuck infection
status: experimental
description: Detects Observables based on Case 5 from TheHive
author: jordisk
references:
    - http://thehive.lab.int:9000/index.html#/case/ADAS3pWuOTfe0bZni0kV/details
date: 2018/08/09
---
logsource:
    category: firewall
detection:
    outgoing: 
        dst_ip:
            - '155.151.29.109'
            - '8.8.8.8'
    incoming: 
        src_ip:
            - '155.151.29.109'
            - '8.8.8.8'
    condition: 1 of them
---
logsource:
    category: dns
detection:
    selection: 
        query: 
            - 'google.co.uk'
            - 'github.com'
            - 'hackmd.io'
    condition: selection
---
logsource:
    category: proxy
detection:
    selection1: 
        UserAgent: 
            - '*(hydra)*'
    condition: selection1
---
logsource:
    product: windows
    service: sysmon
detection:
    selection2: 
        EventID: 
            - 13
            - 12
            - 14
        TargetObject: 
            - 'HKLM\REGISTRY\MACHINE\SOFTWARE\Microsoft\CurrentVersion\Run\wannafuck'
            - 'HKLM\REGISTRY\MACHINE\SOFTWARE\Microsoft\CurrentVersion\Run\wanna*'
    condition: selection2
---
logsource:
    product: windows
    service: sysmon
detection:
    selection3: 
        EventID: 1
        TargetImage: 
            - '*\badcmd.exe'
            - '*\wannafuck.exe'
    condition: selection3
```





 