#!/usr/bin/perl

use strict;
use Net::Nessus::XMLRPC;
use Getopt::Long;

my $user;
my $password;
my $url;
my $lpolicy; my $lreport;
my $verbose=0;

Getopt::Long::Configure ("bundling");
my $result = GetOptions (
	"h|help" => \&help,
	"p|policy" => \$lpolicy,
	"r|report" => \$lreport,
	"u|url=s" => \$url,
	"U|user=s" => \$user,
	"P|password=s" => \$password,
	"v|verbose+"  => \$verbose,	
);

# '' is same as https://localhost:8834/
my $n = Net::Nessus::XMLRPC->new ($url,$user,$password);

die "URL, user or passwd not correct: ".$n->nurl."\n" unless ($n->logged_in);

print STDERR "[n] Logged in\n" if ($verbose>0);

if ($lpolicy) {
	print STDERR "[n] Listing policies\n" if ($verbose>0);
	my $p=$n->policy_list_hash;

	foreach my $i (@{$p}) {
		print $i->{'id'}.":".$i->{'name'}.":".$i->{'owner'}."\n";
	}
}

if ($lreport) {
	print STDERR "[n] Listing reports\n" if ($verbose>0);
	my $reports=$n->report_list_hash;

	foreach my $r (@{$reports}) {
		print $r->{'name'}.":".$r->{'readableName'}.":".$r->{'status'}."\n";
	}
	
}

sub help 
{
	print "$0: List nessus policies and reports\n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 [options] [-u url] <-U user> <-P password> -r -p\n\n";
	print " -r	list reports\n";
	print " -p	list policies\n";
	print " -u <s>	use <s> for URL of Nessus XMLRPC\n";
	print " -U <s>	use <s> for username\n";
	print " -P <s>	use <s> for password\n";
	print " -v	be verbose\n";
	print "\n";
	exit (0);
}
