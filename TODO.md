TODO
====

High
----

 *  Provide a way to process .pcap files
 *  Port from pf::util::dhcp to Net::DHCP::Packet and contribute missing features
 *  Port to App::Cmd (or App::RAD)
 *  Improve output
 *  Provide a way to update the fingerprint database 

    Either fetch from packetfence.org or include the fingerbank repo as a git submodule.

 *  Provide a way to share unknown DHCP fingerprints

OSX port
--------

 *  Make Net::Pcap work

    The thing seems to hang on the loop statement.. More investigation required.


Win port
--------

 *  get rid of 'use POSIX;'


Low
---

 *  Compare with and w/o Readonly::XS for performance
