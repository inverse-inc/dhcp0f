dhcspy
======

Passive DHCP analyzer with OS fingerprinting on the LAN through DHCP


Requirements
------------

* Linux (work in progress for other OS)
* perl 5.8+
* Net::Pcap


Install
-------

1. Install Net::Pcap

   On RHEL / CentOS / Fedora: `yum install perl-Net-Pcap`

   On Debian / Ubuntu: `apt-get install libnet-pcap-perl`

2. `git clone git://github.com/inverse-inc/dhcspy.git`

3. `cd dhcspy/`


Use
---

Note: You need root privileges because we need to bind to a service port.

    sudo ./dhcspy.pl -i <interface>

Run `./dhcspy.pl -h` to see all options described.


Author
------

Olivier Bilodeau, <obilodeau@inverse.ca>


License
-------

Copyright (C) 2012 Inverse inc.

Licensed under the GPLv2 or later. See LICENSE for the full text.

Other elements in extlib/ might carry another license. 
Refer to the individual projects.


Thanks
------

* Francois Proulx for the tool's name
* CISSP Groupies for the tool's name brainstorm

