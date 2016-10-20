# upnp_info.py
## Purpose
This script was written so that anyone can easily find the UPnP servers on their network. While tools like this have and do exist, none are as simple as downloading a file and executing it via Python.

## Dependencies
This script depends on 'requests'. You can install requests via pip:

``
pip install requests
``

## Usage
The script takes no input and is simply executed via python:

``
python upnp_info.py
``

## Troubleshooting
upnp_info.py needs to be able access UDP port 1900. If you aren't getting any results but you think you should be then check your firewall.

## Features
upnp_info.py discovers all UPnP servers within multicast range

```
$ python upnp_info.py 
[+] Discovering UPnP locations
[+] Discovery complete
[+] 11 locations found:
	-> http://192.168.0.254:49152/wps_device.xml
	-> http://192.168.1.217:49153/description.xml
	-> http://192.168.1.217:35848/rootDesc.xml
	-> http://192.168.1.217:32469/DeviceDescription.xml
	-> http://192.168.1.217:49152/tvdevicedesc.xml
	-> http://192.168.1.217:35439/rootDesc.xml
	-> http://192.168.1.251:49451/luaupnp.xml
	-> http://192.168.1.1:45973/rootDesc.xml
	-> http://192.168.1.1:1990/WFADevice.xml
	-> http://192.168.1.1:1901/root.xml
	-> http://192.168.1.217:8200/rootDesc.xml
```
It parses the service's XML and displays it for the user:

```
[+] Loading http://192.168.1.217:49153/description.xml...
	-> Server String: Linux/4.4.0-36-generic, UPnP/1.0, MediaTomb/0.12.2
	==== XML Attributes ===
	-> Device Type: urn:schemas-upnp-org:device:MediaServer:1
	-> Friendly Name: MediaTomb
	-> Manufacturer: (c) 2005-2008 Gena Batyan <bgeradz@mediatomb.cc>, Sergey Bostandzhyan <jin@mediatomb.cc>, Leonhard Wimmer <leo@mediatomb.cc>
	-> Manufacturer URL: http://mediatomb.cc/
	-> Model Description: Free UPnP AV MediaServer, GNU GPL
	-> Model Name: MediaTomb
	-> Model Number: 0.12.2
	-> Services:
		=> Service Type: urn:schemas-upnp-org:service:ConnectionManager:1
		=> Control: /upnp/control/cm
		=> Events: /upnp/event/cm
		=> API: http://192.168.1.217:49153/cm.xml
			- GetCurrentConnectionIDs
			- GetCurrentConnectionInfo
			- GetProtocolInfo
		=> Service Type: urn:schemas-upnp-org:service:ContentDirectory:1
		=> Control: /upnp/control/cds
		=> Events: /upnp/event/cds
		=> API: http://192.168.1.217:49153/cds.xml
			- Browse
			- GetSearchCapabilities
			- GetSortCapabilities
			- GetSystemUpdateID
```
It can browse file shares:

```
[+] Content browsing available. Looking up base directories...
		Storage Folder: PC Directory
		Storage Folder: Photos
		Storage Folder: wat
```

It can show port mappings:

```
[+] IGD port mapping available. Looking up current mappings...
		[UDP] *:60579 => 192.168.1.186:60579 | Desc: None
```

## License
The license is BSD 3-clause. See the LICENSE file for details.
