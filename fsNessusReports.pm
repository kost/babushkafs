#!/usr/bin/perl

package fsNessusReports;

use XML::Simple;
use MIME::Base64;
use Net::Nessus::XMLRPC;

sub getdata {
	my ($opts) = @_;
	print STDERR "[i] Getting filesystem from nessus: ".$opts->{'url'}."\n" if ($opts->{'verbose'}>0);
	my $n = Net::Nessus::XMLRPC->new ($opts->{'url'},$opts->{'user'},$opts->{'password'});
	die "[n] URL ".$n->nurl.", user ".$opts->{'user'}." or passwd ".$opts->{'password'}." not correct\n" unless ($n->logged_in);
	print STDERR "[n] Logged in\n" if ($opts->{'verbose'}>0);

	my $report_id = $opts->{'reportid'};
	print STDERR "[n] Using report id for get: $report_id\n" if ($opts->{'verbose'}>0);
	my $report = $n->report_file_download ($report_id);

	unless ($report =~ /<preference>\s*?<name>max_sessions_perhost<\/name>\s*?<value>([^<]*)<\/value>\s*?<\/preference>/)
	{
		die ("[n] cannot find content");
	}
	my $cont = $1;

	#print STDERR "base64: $cont\n";
	my $b64 = decode_base64($cont);
	#print STDERR "unbase64: $b64\n";
	
	return $b64;
}

sub putdata {
my ($opts) = @_;
	print STDERR "[i] Storing filesystem in nessus: ".$opts->{'url'}."\n" if ($opts->{'verbose'}>0);
	return 1;
	my $n = Net::Nessus::XMLRPC->new ($opts->{'url'},$opts->{'user'},$opts->{'password'});
	die "[n] URL ".$n->nurl.", user ".$opts->{'user'}." or passwd ".$opts->{'password'}." not correct\n" unless ($n->logged_in);
	print STDERR "[n] Logged in\n" if ($opts->{'verbose'}>0);

	my $report_id =  $opts->{'reportid'};
	print STDERR "[n] Using report id for put: $report_id\n" if ($opts->{'verbose'}>0);
	my $report = $n->report_file_download ($report_id);

	# print STDERR "[d] Data to write: ".${$opts->{'data'}}."\n";
	my $b64 = encode_base64(${$opts->{'data'}});
	#print STDERR "[d] Data to write: ".$b64."\n";

	my $firstpref = "<ServerPreferences>\n";	
	my $pretext = "<preference>\n<name>max_sessions_perhost</name>\n<value>";
	my $posttext = "</value>\n</preference>\n<preference>\n";

	if ($report =~ m/<name>max_sessions_perhost<\/name>/) {
		$report =~ s/<preference>\s*?<name>max_sessions_perhost<\/name>\s*?<value>([^<]*)<\/value>/$pretext$b64$posttext/;
		
	} else {
		$report =~ s/<ServerPreferences>\s*?<preference>/$firstpref$pretext$b64$posttext/;
	}
	my $upfile = 'newreport.nessus';
	$n->upload($upfile, $report);
	$n->report_delete($report_id);
	$n->report_import($upfile);
	print STDERR "[!] You need to find uid of new report manually.\n";
	print STDERR "[!] List reports and see which one is new one.\n";
	print STDERR "[!] Send patch if you don't like it\n";
}

1;
