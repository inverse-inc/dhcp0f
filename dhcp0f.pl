#!/usr/bin/perl 

=head1 NAME

dhcp0f.pl - Passive DHCP analyzer with OS fingerprinting on the LAN through DHCP

=head1 SYNOPSIS

dhcp0f.pl [options]

 Options:
   -k      Fingerbank API key
   -i      Interface (default: "eth0")
   -f      Filter (eg. "host 128.103.1.1")
   -c      CHADDR (show requests from specific client)
   -t      DHCP message type
             Value   Message Type
             -----   ------------
               1     DHCPDISCOVER
               2     DHCPOFFER
               3     DHCPREQUEST
               4     DHCPDECLINE
               5     DHCPACK
               6     DHCPNAK
               7     DHCPRELEASE
               8     DHCPINFORM
   -v      verbose 
   -h      Help

=cut
require 5.8.0;

use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin . '/lib';
use lib $FindBin::Bin . '/extlib';

use Config::IniFiles;
use Data::Dumper;
use File::Basename qw(basename);
use Getopt::Std;
use Log::Log4perl qw(:easy :no_extra_logdie_message);
use Net::Pcap 0.16;
use Pod::Usage;
use POSIX;
use Try::Tiny;

use Util qw(clean_mac);
use pf::util::dhcp;

my %args;
getopts( 'k:t:i:f:c:o:huv', \%args );

my $verbose = $INFO;
if ( $args{v} ) {
    $verbose = $DEBUG;
}

Log::Log4perl->easy_init({ level  => $verbose, layout => '%m%n' });
my $logger = Log::Log4perl->get_logger('');                                                                             

my $fingerbank = 0;
if ( $args{k} ) {
    require fingerbank::api;
    $fingerbank = 1;
}

my $interface = $args{i} || "eth0";

if ( $args{h} || !$interface ) {
    pod2usage( -verbose => 1 );
}

my $chaddr_filter;
if ( $args{c} ) {
    $chaddr_filter = clean_mac( $args{c} );
}
my $filter = "(udp and (port 67 or port 68))";
if ( $args{f} ) {
    $filter .= " and " . $args{f};
}
my $type;
if ( $args{t} ) {
    $type = $args{t};
}
my $unknown;
if ( $args{u} ) {
    $unknown = 1;
}
my %msg_types;
$msg_types{'1'}   = "subnet mask";
$msg_types{'3'}   = "router";
$msg_types{'4'}   = "time server";
$msg_types{'6'}   = "dns servers";
$msg_types{'12'}  = "hostname";
$msg_types{'15'}  = "domain";
$msg_types{'23'}  = "default ttl";
$msg_types{'28'}  = "broadcast";
$msg_types{'31'}  = "router discovery";
$msg_types{'43'}  = "vendor specific information (43)";
$msg_types{'44'}  = "netbios nameserver";
$msg_types{'46'}  = "netbios node type";
$msg_types{'50'}  = "requested ip address";
$msg_types{'51'}  = "address time";
$msg_types{'53'}  = "message type";
$msg_types{'54'}  = "dhcp server id";
$msg_types{'55'}  = "requested parameter list";
$msg_types{'57'}  = "dhcp max message size";
$msg_types{'58'}  = "renewal time";
$msg_types{'59'}  = "rebinding time";
$msg_types{'60'}  = "vendor id";
$msg_types{'61'}  = "client id";
$msg_types{'66'}  = "servername";
$msg_types{'67'}  = "bootfile";
$msg_types{'81'}  = "fqdn";
$msg_types{'82'}  = "agent information (82)";
$msg_types{'150'} = "cisco tftp server (150)";
$msg_types{'116'} = "dhcp auto-config";

my $filter_t;
my $net;
my $mask;
my $opt = 1;
my $err;

my $pcap_t = Net::Pcap::pcap_open_live($interface, 576, 1, 0, \$err)
    or $logger->logdie("Unable to open network capture: $err");

if ( ( Net::Pcap::compile( $pcap_t, \$filter_t, $filter, $opt, 0 ) ) == -1 ) {
    $logger->logdie("Unable to compile filter string '$filter'");
}

Net::Pcap::setfilter( $pcap_t, $filter_t );

$logger->info("Starting to listen on $interface with filter: $filter");
Net::Pcap::loop( $pcap_t, -1, \&process_pkt, $interface );

sub process_pkt {
    my ( $user_data, $hdr, $pkt ) = @_;
    listen_dhcp( $pkt, $user_data );
}

sub listen_dhcp {
    my ( $packet, $eth ) = @_;
    $logger->debug("Received packet on interface");

    my ($l2, $l3, $l4, $dhcp);

    # we need success flag here because we can't next inside try catch
    my $success;
    try {
        ($l2, $l3, $l4, $dhcp) = decompose_dhcp($packet);
        $success = 1;
    } catch {
        $logger->warn("Unable to parse DHCP packet: $_");
    };
    return if (!$success);

    # chaddr filter
    $dhcp->{'chaddr'} = clean_mac( substr( $dhcp->{'chaddr'}, 0, 12 ) );
    return if ( $chaddr_filter && $chaddr_filter ne $dhcp->{'chaddr'});

    return if ( !$dhcp->{'options'}{'53'} );

    # DHCP Message Type filter
    return if ( $type && $type ne $dhcp->{'options'}{'53'} );

    $logger->info(POSIX::strftime( "%Y-%m-%d %H:%M:%S", localtime ));
    $logger->info("-" x 80);
    $logger->info(sprintf("Ethernet\tsrc:\t%s\tdst:\t%s", clean_mac($l2->{'src_mac'}), clean_mac($l2->{'dest_mac'})));
    $logger->info(sprintf("IP\t\tsrc: %20s\tdst: %20s", $l3->{'src_ip'}, $l3->{'dest_ip'}));
    $logger->info(sprintf("UDP\t\tsrc port: %15s\tdst port: %15s", $l4->{'src_port'}, $l4->{'dest_port'}));
    $logger->info("-" x 80);
    $logger->info(dhcp_summary($dhcp));
    $logger->debug(Dumper($dhcp));

    foreach my $key ( keys(%{ $dhcp->{'options'} }) ) {
        my $tmpkey = $key;
        $tmpkey = $msg_types{$key} if ( defined( $msg_types{$key} ) );

        my $output;
        if (ref($dhcp->{'options'}{$key}) eq 'ARRAY') {
            $output = join( ",", @{ $dhcp->{'options'}{$key} } );

        } elsif (ref($dhcp->{'options'}{$key}) eq 'SCALAR') {
            $output = ${$dhcp->{'options'}{$key}};

        } elsif (ref($dhcp->{'options'}{$key}) eq 'HASH') {
            $output = Dumper($dhcp->{'options'}{$key});

        } elsif (!ref($dhcp->{'options'}{$key})) {
            $output = $dhcp->{'options'}{$key};
        }
        unless ( !$output ) {
            $logger->info( "$tmpkey: $output" );
        }
    }
    $logger->info("TTL: $l3->{'ttl'}");

    my $dhcp_fingerprint = $dhcp->{'options'}{'55'};
    my $dhcp_vendor = $dhcp->{'options'}{'60'};
    $logger->info("DHCP fingerprint: " . ( defined($dhcp_fingerprint) ? $dhcp_fingerprint : 'None' ));
    $logger->info("DHCP vendor: " . ( defined($dhcp_vendor) ? $dhcp_vendor : 'None' ));

    if ( $fingerbank ) {
        my $fingerbank_result = fingerbank::api::query($args{k}, {dhcp_fingerprint => $dhcp_fingerprint, dhcp_vendor => $dhcp_vendor});

        if(defined($fingerbank_result)) {
            my $fingerbank_device = join('/', reverse(map {$_->{name}} @{$fingerbank_result->{device}->{parents}})) . '/' . $fingerbank_result->{device}->{name};
            $logger->info("Fingerbank device : $fingerbank_device (".$fingerbank_result->{device}->{id}.")");
            my $fingerbank_version = $fingerbank_result->{version} // 'Unknown';
            $logger->info("Fingerbank device version : ".$fingerbank_version);
            $logger->info("Fingerbank device score : ".$fingerbank_result->{score});
        }
        else {
            $logger->info("Fingerbank device unknown");
        }
    }
    $logger->info("=" x 80);
}

=head1 AUTHOR

Inverse inc.

=head1 COPYRIGHT

Copyright (C) 2009-2016 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

