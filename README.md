# WifiPicket

Stop people from connecting to unsecure/unwanted hotspots. If you have your kids/family/employees using neighbourhood wifis to circuimvent your network policies, this is the tool you want.
It will continuously disassociate all or selected wifi clients and access points within range, forcing good behavior.

## Features
* Watch/sniff the wifi on all channels, including AC 5Gh.
* Drop selected clients by MAC (blacklisting). If it sees traffic from any known MAC, check if it's talking to your AP's mac. If it is not, send a disassociation packet from the MAC that it's talking to.
* Drop all clients and hotspots, except selected (whitelisting)
* Can run on small platforms. Tested on a Raspberry Pi with TP-LINK's TL-WN722N.


## Setting up

You will need python 2.7, python-scapy and a wifi-card capable of sniffing and injection. Recommended (and tested) cards are:
* For 802.11n - TP-Link Wireless N150 High Gain USB Adapter, 150Mbps, 4dBi External Antenna, WPS Button, Supports Windows XP/Vista/7/8 (TL-WN722N). Uses Atheros AR9271 chipset
* For 802.11ac - Alfa Long-Range Dual-Band AC1200 Wireless USB 3.0 Wi-Fi Adapter w/2x 5dBi External Antennas - 2.4GHz 300Mbps / 5Ghz 867Mbps

Effectiveness of this script depends directly on the wifi card you have.

On raspbian do
`sudo apt-get install python-scapy tcpdump wireless-tools`

Note that running it on a small CPU like RPi will likely require a whitelist filter (pcap-filter list of MACs to watch for), otherwise it would likely overload the CPU on trying to parse all wifi traffic in the air.
You could try to compile it with nutika to squeeze some performance out, but in my tests the gains were negligible.

## Running

``` shell
python -u wifipicket.py
```
Find all hotspots and all clients and disassociate them. This is effectively a total wifi jammer mode.

```shell
python wifipicket.py -a evilhotspot -c 2
```
Deauthenticate all devices with from a known hotspot on a known channel. Can also be used to stop a known client from connecting to anything.


``` shell
python -u wifipicket.py -a opennet -i wlan0 -m 10:12:12:12:10:aa 10:12:12:12:10:bb
```
Prevent known clients from connecting to the 'opennet' hotspot. Limiting clients lowers the CPU use and makes deauth more reliable on platfroms like RPi

All options:
```
-i or --interface - Choose monitor mode interface. By default script will find the most powerful interface and starts monitor mode on it. Example: -i mon5
-c or --channel - Listen on and deauth only clients on the specified channel. Example: -c 6
-t or --timeinterval - Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001
-p or --packets - Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2
-d or --directedonly - Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs
-a or --accesspoint - Enter the SSID or MAC addresses of a specific access points to target. SSID will match multiple APs if they share the same SSID
-m or --mac - Limit to specific MACs through BPF (pcap-filter). Can provide many separated by space. Can be combined with -a to target specific clients on specific APs.
-s or --skip - Skip deauthing these MAC addresses. Example: -s 00:11:BB:33:44:AA
-q or --quiet - Be silent. To show status do sudo kill -USR1 $(cat "+pidfile+")
-v or --verbose - Print packets and other debug stuff
--wide - Enable scanning of 13 channels in the N range. By default North American standard of 11 channels is used
--ac - Add 802.11ac North American 5Ghz channels to the scan list. Please note that it may include channels not allowed in other parts of the world. Check wikipedia's 'List of WLAN channels'.
--persistent - Keep disconnecting the client even if it is no longer connected.
--dry-run - Do not deauth anyone, just monitor and report
```

## Respect
Loosely based on Dan McInerney's wifijammer
