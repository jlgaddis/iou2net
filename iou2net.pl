#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long;
use Net::Pcap;
use IO::Socket;

my $version = "v0.21";
my $version_date = "26-Jan-2011";

###################################################################################
# CHANGES
# =======
#
# v0.21, 26-Jan-2011
# -----------------
# - changed socket_base handling after receiving hint that "1000" is the uid
#   that IOU is started with ;-)
#
# v0.2, 24-Jan-2011
# -----------------
# - added pcap filter to allow for better performance on busy nics
#
# v0.1, 23-Jan-2011
# -----------------
# - first release
#
###################################################################################

my $help = <<EOF;

iou2net.pl: bridge between iou and real networks (IOUlive replacement)
Version $version, $version_date.

usage:
iou2net.pl -i <network interface> -n [<IOU NETMAP file>] -p <IOU pseudo instance ID>

-i <network interface>
The NIC you want to bridge to/from. You need superuser privileges to do that.

-n <IOU NETMAP file> (optional)
A NETMAP file is always needed, because the original IOU instance must be determined
by the script. Without this parameter, the script tries to open the NETMAP file from
the current directory. If you want to use a file in a different location, use this
parameter.

-p <IOU pseudo instance ID>
IOU requires a pseudo instance for this. When bridging your IOU router interface,
specify an unused ID as the target in your NETMAP file, like

1:2/1\@hobel	666:1/0\@hobel

666 is the pseudo IOU instance ID, hobel is the host where the IOU and the script
runs at. When starting the script, use 666 then.

CAVEATS: For now, you need to use x/y interface format in the NETMAP file, at least for
the mapping this script requires. Also, for bridging multiple router interfaces, separate
instances of this script must be launched, and you need an unique pseudo IOU ID per
instance.

EOF

my $err;
my $pcap_recv_data;
my $iou_recv_data;
my $iou_header;
my $iface;
my $netmap_file = "./NETMAP";
my $netmap_handle;
my $socket_base;
my $pseudo_instance;
my $pseudo_instance_interface_major;
my $pseudo_instance_interface_minor;
my $iou_instance;
my $iou_interface_major;
my $iou_interface_minor;
my $pcap_filter;

GetOptions(	'help'		=>	sub{ print"$help"; exit(0); },
		'i=s'		=>	\$iface,
		'n=s'		=>	\$netmap_file,
		'p=i'		=>	\$pseudo_instance
);

die "\nPlease provide -i and -p!\n$help" unless ($iface && $pseudo_instance);		

# socket directory is a directory below $TMPDIR (/tmp), composed of "netio" plus
# uid of the user that runs the iou binary
# since we assume this script gets invoked with sudo by most people:
# try to be smart about getting real UID, $< does not (always?) return real uid when using sudo

$socket_base = $ENV{SUDO_UID};
$socket_base = $< unless (defined $socket_base);        # apparently not started with sudo
$socket_base = "/tmp/netio$socket_base";

open (netmap_handle, $netmap_file) or die "Can't open netmap file $netmap_file\n";

# walk through NETMAP file and try to determine the source IOU instance
while (<netmap_handle>)
{
	# stop when there is a match for our pseudo instance ID as the destination
	next if !($_ =~ m/^\d+:\d+\/\d+@\w+[ \t]+$pseudo_instance:\d+\/\d+@\w+(\s|\t)*$/);	
 	my $inputline = $_;
        chomp($inputline);

	# we just ignore any hostname statements
	$inputline =~ s/\@\w+//g;

        my @connline = split (/[ \t]+/, $inputline);
        $connline[0] =~ s/(\s\t)*//g;
        $connline[1] =~ s/(\s\t)*//g;
        my @iou_src = split (/:/, $connline[0]);
        my @iou_dst = split (/:/, $connline[1]);
	$iou_instance = $iou_src[0];
	($iou_interface_major,$iou_interface_minor) = split (/\//, $iou_src[1]);
	($pseudo_instance_interface_major,$pseudo_instance_interface_minor) =  split (/\//, $iou_dst[1]);
}

close (netmap_handle);

die "Could not find any valid mapping for IOU pseudo instance $pseudo_instance in NETMAP file" unless ((defined $iou_instance) && (defined $iou_interface_major) && (defined $iou_interface_minor) && (defined $pseudo_instance_interface_major) && (defined $pseudo_instance_interface_minor));

# unlink socket for IOU pseudo instance
unlink "$socket_base/$pseudo_instance";

# create socket for IOU pseudo instance
my $iou_pseudo_sock = IO::Socket::UNIX->new(Type=>SOCK_DGRAM, Listen=>5, Local=>"$socket_base/$pseudo_instance") or die "Can't create IOU pseudo socket\n";
# allow anyone to read and write
chmod 0666, "$socket_base/$pseudo_instance";

# attach to real IOU instance
my $iou_router_sock = IO::Socket::UNIX->new(Type=>SOCK_DGRAM, Peer=>"$socket_base/$iou_instance") or die "Can't connect to IOU socket at $socket_base/$iou_instance\n";

# precompute IOU header
# IOU header format
# Pos (byte)	value
# ==============================================================
# 00 - 01	destination (receiving) IOU instance ID
# 02 - 03	source (sending) IOU instance ID
# 04		receiving interface ID
# 05		sending interface ID
# 06 - 07	fixed delimiter, looks like its always 0x01 0x00
#
#               interface ID = <major int number> + (<minor int number> * 16)
	
$iou_header = sprintf("%04x",$iou_instance) . sprintf ("%04x", $pseudo_instance);
$iou_header .= sprintf ("%02x", ($iou_interface_major + ($iou_interface_minor * 16)));
$iou_header .= sprintf ("%02x", ($pseudo_instance_interface_major + ($pseudo_instance_interface_minor * 16)));
$iou_header .= "0100";
$iou_header = pack("H*", $iou_header);

# bind to network interface, promiscuous mode
my $pcap = Net::Pcap::open_live($iface, 1522, 1, 100, \$err);
die "pcap: can't open device $iface: $err (are you root?)\n"	if(not defined $pcap);

# receive IOU frame and send to real network
# we fork this, so traffic can be received and processed via pcap in the pcap loop below

my $iou_pseudo_fork = fork();
if ($iou_pseudo_fork == 0)
{
	while (1)
	{
		# IOU frame received via pseudo ID socket
		$iou_pseudo_sock->recv($iou_recv_data,1522);

		# cut off IOU header (first 8 bytes)
		$iou_recv_data =~ s/^.{8}//;
		
		# send IOU generated frame to real network
		Net::Pcap::sendpacket($pcap,$iou_recv_data);
	}
	exit(0);
}

# provide a clean exit when user sends break
$SIG{INT} = \&pcap_sigint;

# build a packet filter for IOU MAC OID
# this will match only what is destined to 0E:00:03:E8, plus multicast and broadcasts
Net::Pcap::compile($pcap, \$pcap_filter, '(ether[0] & 1 = 1) or (ether[0:4] = 0x0e0003e8)', 0, 0xFFFFFFFF) && die 'Unable to compile capture filter';
Net::Pcap::setfilter($pcap, $pcap_filter) && die 'Unable to assign capture filter';

print "Forwarding frames between interface $iface and IOU instance $iou_instance, int $iou_interface_major/$iou_interface_minor -  press ^C to exit\n";

# define infinite loop for capturing network traffic
my $loop_exit = Net::Pcap::loop($pcap, -1, \&recv_loop, $pcap_recv_data);

sub recv_loop
{
	my($user_data, $hdr, $pkt) = @_;

	# add IOU header in front of the received frame
	my $iou_frame = $iou_header . "$pkt";
	
	# send frame to IOU socket
	$iou_router_sock->send($iou_frame);
	
}

sub pcap_sigint
{
	Net::Pcap::breakloop($pcap);
	print "\n...stopped by user.\n";
	Net::Pcap::close($pcap);
	$iou_pseudo_sock->close;
	$iou_router_sock->close;
	kill 1, $iou_pseudo_fork;
	exit(0);
}
