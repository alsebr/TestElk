1. Ищем 

фикацию syslog CEF
https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557?attachment-id=68077
2. Открываем паттерны GROK
https://github.com/elastic/logstash/blob/v1.4.2/patterns/grok-patterns
3. Для дебага GROK используем:
https://grokdebug.herokuapp.com/
4. Сообщение:
```
Oct 21 15:12:07 vnetids emerg CEF:0|InfoTeCS|IDS|9.4.9-99999|1:2019401:27|ET POLICY Vulnerable
Java Version 1.8.x Detected|2|cat=1 cn1=1234567 cn1Label=EventID cnt=1 cs1=bad-unknown
cs1Label=IDSClass cs2=emerging-policy cs2Label=IDSGroup cs3= cs3Label=CVEID
cs4=url,www.oracle.com/technetwork/java/javase/8u-relnotes-2225394.html cs4Label=ExternalRef
cs5= cs5Label=IDSTags deviceExternalId=123456789 deviceFacility=Signature dmac=33:33:33:33:33:33
dpt=80 dst=199.199.199.199 proto=TCP rt=Oct 21 2019 15:12:05.750 MSK smac=00:00:00:00:00:00
spt=00000 src=99.99.99.99
```
!!! Не смог понять, почему название хоста в предлагаемом событии "vnetids emerg" содержит пробел. Насколько я понял, это противоречит спецификации. Решил убрать пробел.

Напоминалка по формату:
Jan  18   11:07:53 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

5. Начинаем парсить:  
```
%{SYSLOGTIMESTAMP:syslog_time}  
%{HOSTNAME:syslog_hostname}  
```
Смотрим спецификацию по версии:  
>Version is  an integer and identifies the version of the CEF format. Event consumers use this information to determine what the following fields represent. The current CEF version is 0 (CEF:0).    
```
CEF:%{INT:cef_version}
```
6. Не забываем делиметр "|" экранировать.
>Device Vendor, Device Product and Device Version are strings that uniquely identify the type of sending device. No two products may use the same device-vendor and device-product pair. There is no central authority managing these pairs. Event producers must ensure that they assign unique name pairs.
 
Точного описания что у них значит String не нашел, будем считать, что в данном контексте: [^\|]+  
Вводим новый паттерн:  
STRINGDELIM [^\|]+  
Итого на данный момент:  
```
%{SYSLOGTIMESTAMP:syslog_time} %{HOSTNAME:syslog_hostname} CEF:%{INT:cef_version}\|%{STRINGDELIM:device_vendor}\|%{STRINGDELIM:device_product}\|%{STRINGDELIM:device_version}
```
7.
>Device Event Class ID is  a unique identifier per event-type. This can be a string or an integer. Device Event Class ID identifies the type of event reported. In the intrusion detection system (IDS)world, each signature or rule that detects certain activity has a unique Device Event Class ID assigned. This is    a   requirement for other types of devices as   well, and helps correlation enginesprocess the events. Also known as Signature ID.

Видимо, то же String, так-что:  
```%{STRINGDELIM:device_event_class_id}  ```

8.
>Name is    a   string representing a human-readable and understandable description of the event. The event name should not contain information that is specifically mentioned in other fields. For example: "Port scan from 10.0.0.1 targeting 20.1.1.1" is not a good event name. It should be: "Portscan". The other information is redundant and can be picked up from the other fields.

```%{STRINGDELIM:event_name}```

9.
>Severity is  a   string or integer and reflects the importance of the event. The valid string values are Unknown, Low, Medium, High, and Very-High. The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.

Доавляем новый паттерн:  
Unknown|Low|Medium|High|Very-High|10|[0-9]  
Получаем:  
```%{SEVERITY:severity}```

10.
>TheExtensionfield contains a collection of key-value pairs. The keys are part of a predefined set.The standard allows for including additional keys as   outlined in “ArcSight Extension Directory” later in this document.  An event can contain any number of key-value pairs in any order, separated by spaces ("  ")  

>If   a field contains a space, such as   a file name, this is valid and can be logged in exactly thatmanner, as   shown below
```%{GREEDYDATA:message}```
Здесь GROK пасует. Отдаем message на откуп Kv Filter  

Итого:  
IN:  
```Oct 21 15:12:07 vnetidsemerg CEF:0|InfoTeCS|IDS|9.4.9-99999|1:2019401:27|ET POLICY Vulnerable
Java Version 1.8.x Detected|2|cat=1 cn1=1234567 cn1Label=EventID cnt=1 cs1=bad-unknown cs1Label=IDSClass cs2=emerging-policy cs2Label=IDSGroup cs3= cs3Label=CVEID cs4=url,www.oracle.com/technetwork/java/javase/8u-relnotes-2225394.html cs4Label=ExternalRef cs5= cs5Label=IDSTags deviceExternalId=123456789 deviceFacility=Signature dmac=33:33:33:33:33:33 dpt=80 dst=199.199.199.199 proto=TCP rt=Oct 21 2019 15:12:05.750 MSK smac=00:00:00:00:00:00
spt=00000 src=99.99.99.99
```
GROK FILTER:
```%{SYSLOGTIMESTAMP:syslog_time} %{HOSTNAME:syslog_hostname} CEF:%{INT:cef_version}\|%{STRINGDELIM:device_vendor}\|%{STRINGDELIM:device_product}\|%{STRINGDELIM:device_version}\|%{STRINGDELIM:device_event_class_id}\|%{STRINGDELIM:event_name}\|%{SEVERITY:severity}\|%{GREEDYDATA:message}
```
+PATTERNS:
```
STRINGDELIM [^\|]+
SEVERITY Unknown|Low|Medium|High|Very-High|[0-9]
```
OUT:
```
{
  "syslog_time": [
    [
      "Oct 21 15:12:07"
    ]
  ],
  "MONTH": [
    [
      "Oct"
    ]
  ],
  "MONTHDAY": [
    [
      "21"
    ]
  ],
  "TIME": [
    [
      "15:12:07"
    ]
  ],
  "HOUR": [
    [
      "15"
    ]
  ],
  "MINUTE": [
    [
      "12"
    ]
  ],
  "SECOND": [
    [
      "07"
    ]
  ],
  "syslog_hostname": [
    [
      "vnetidsemerg"
    ]
  ],
  "cef_version": [
    [
      "0"
    ]
  ],
  "device_vendor": [
    [
      "InfoTeCS"
    ]
  ],
  "device_product": [
    [
      "IDS"
    ]
  ],
  "device_version": [
    [
      "9.4.9-99999"
    ]
  ],
  "device_event_class_id": [
    [
      "1:2019401:27"
    ]
  ],
  "event_name": [
    [
      "ET POLICY Vulnerable\nJava Version 1.8.x Detected"
    ]
  ],
  "severity": [
    [
      "2"
    ]
  ],
  "message": [
    [
      "cat=1 cn1=1234567 cn1Label=EventID cnt=1 cs1=bad-unknown cs1Label=IDSClass cs2=emerging-policy cs2Label=IDSGroup cs3= cs3Label=CVEID cs4=url,www.oracle.com/technetwork/java/javase/8u-relnotes-2225394.html cs4Label=ExternalRef cs5= cs5Label=IDSTags deviceExternalId=123456789 deviceFacility=Signature dmac=33:33:33:33:33:33 dpt=80 dst=199.199.199.199 proto=TCP rt=Oct 21 2019 15:12:05.750 MSK smac=00:00:00:00:00:00"
    ]
  ]
}
```
