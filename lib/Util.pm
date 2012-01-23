package Util;
=head1 NAME

Util - generic functions and utilities

=cut

=head1 DESCRIPTION

Util contains many functions and utilities used by the other different modules. 

=cut
use strict;
use warnings;

BEGIN {
    use Exporter ();
    our (@ISA, @EXPORT, @EXPORT_OK);
    @ISA = qw(Exporter);
    @EXPORT = qw();
    @EXPORT_OK = qw(int2ip clean_mac);
}

# FIXME these two were crudely copied from pf::util because the rest of 
# pf::util is not portable at this moment and I couldn't find a simple 
# replacement

sub int2ip {
    return ( join( ".", unpack( "C4", pack( "N", shift ) ) ) );
}

=item clean_mac 

Clean a MAC address accepting xxxxxxxxxxxx, xx-xx-xx-xx-xx-xx, xx:xx:xx:xx:xx:xx, xxxx-xxxx-xxxx and xxxx.xxxx.xxxx.

Returns an untainted string with MAC in format: xx:xx:xx:xx:xx:xx

=cut
sub clean_mac {
    my ($mac) = @_;
    return (0) if ( !$mac );

    # trim garbage
    $mac =~ s/[\s\-\.:]//g;
    # lowercase
    $mac = lc($mac);
    # inject :
    $mac =~ s/([a-f0-9]{2})(?!$)/$1:/g if ( $mac =~ /^[a-f0-9]{12}$/i );
    # Untaint MAC (see perldoc perlsec if you don't know what Taint mode is)
    if ($mac =~ /^([0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}:[0-9a-zA-Z]{2})$/) {
        return $1;
    }

    return;
}
 
=head1 AUTHOR

Olivier Bilodeau <obilodeau@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2009-2011 Inverse inc.

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

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
