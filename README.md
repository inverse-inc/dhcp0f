dhcp0f
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

2. `git clone git://github.com/inverse-inc/dhcp0f.git`

3. `cd dhcp0f/`


Use
---

Note: You need root privileges because we need to bind to a service port.

    sudo ./dhcp0f.pl -i <interface>

Run `./dhcp0f.pl -h` to see all options described.


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

* Julien Desfossez for the tool's name (with an honorable mention to Francois Proulx's idea dhcspy)
* CISSP Groupies for the tool's name brainstorm

