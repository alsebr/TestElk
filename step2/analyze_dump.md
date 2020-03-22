1. Готовим инструментарий:  
* Wireshark  
* Moloch  
* Suricata (enable'им правил по максимум на всякий случай.  
2. При помощи Moloch смотрим общие данные по дампу и какие хосты есть в сетке, кто чем занимается.  
Начало: 2020/03/09 02:49 GMT +5  
Длительность: <10 мин  
Хосты в серой сетке:  
* 192.168.0.3
* 192.168.0.13
Судя по адресации - виртуалки.  
* 10.0.20.229 - видимо гипервизор. ICMP пакеты проскочили
  
Из интересного:  
через GDVDTRK.RU(редиректит на google) ктото искал virustotal  
3. Запускаем сурикату на дамп трафика, чистим мусор. Остается:
```
03/09/2020-02:50:19.969481  [**] [1:2027863:3] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.0.13:63428 -> 192.168.0.1:53
03/09/2020-03:02:17.592703  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:43470 -> 192.168.0.13:139
03/09/2020-03:02:17.592703  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:43470 -> 192.168.0.13:139
03/09/2020-03:02:17.593159  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:40686 -> 192.168.0.13:445
03/09/2020-03:02:17.593159  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:40686 -> 192.168.0.13:445
03/09/2020-03:02:18.906850  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:39150 -> 192.168.0.13:49152
03/09/2020-03:02:18.906850  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:39150 -> 192.168.0.13:49152
03/09/2020-03:02:19.113334  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:50968 -> 192.168.0.13:49153
03/09/2020-03:02:19.113334  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:50968 -> 192.168.0.13:49153
03/09/2020-03:02:19.220139  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:53954 -> 192.168.0.13:7200
03/09/2020-03:02:19.220139  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:53954 -> 192.168.0.13:7200
03/09/2020-03:02:17.595218  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:35058 -> 192.168.0.13:49158
03/09/2020-03:02:17.595218  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:35058 -> 192.168.0.13:49158
03/09/2020-03:02:17.595797  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:44318 -> 192.168.0.13:49157
03/09/2020-03:02:17.595797  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:44318 -> 192.168.0.13:49157
03/09/2020-03:02:17.595825  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:45922 -> 192.168.0.13:49154
03/09/2020-03:02:17.595825  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:45922 -> 192.168.0.13:49154
03/09/2020-03:02:17.592276  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:35838 -> 192.168.0.13:21
03/09/2020-03:02:17.592276  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:35838 -> 192.168.0.13:21
03/09/2020-03:02:17.592282  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:39782 -> 192.168.0.13:135
03/09/2020-03:02:17.592282  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:39782 -> 192.168.0.13:135
03/09/2020-03:02:18.696609  [**] [1:2210045:2] SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:57290 -> 192.168.0.13:49155
03/09/2020-03:02:18.696609  [**] [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.0.3:57290 -> 192.168.0.13:49155
```
Видимо это скан портов.
