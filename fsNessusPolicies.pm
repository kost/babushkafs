#!/usr/bin/perl

package fsNessusPolicies;

use XML::Simple;
use MIME::Base64;
use Net::Nessus::XMLRPC;

sub getdata {
	my ($opts) = @_;
	print STDERR "[i] Getting filesystem from nessus: ".$opts->{'url'}."\n" if ($opts->{'verbose'}>0);
	my $n = Net::Nessus::XMLRPC->new ($opts->{'url'},$opts->{'user'},$opts->{'password'});
	die "[n] URL ".$n->nurl.", user ".$opts->{'user'}." or passwd ".$opts->{'password'}." not correct\n" unless ($n->logged_in);
	print STDERR "[n] Logged in\n" if ($opts->{'verbose'}>0);

	my $policy_id = $opts->{'policyid'};

	print STDERR "[n] Using policy id for get: $policy_id\n" if ($opts->{'verbose'}>0);
	my $policy = $n->policy_get_opts ($policy_id);

	unless ($policy->{'max_sessions_perhost'})
	{
		die ("[n] cannot find content");
	}
	my $b64 = decode_base64($policy->{'max_sessions_perhost'});
	# print STDERR "unbase64: $b64\n";
	return $b64;
}

sub putdata {
my ($opts) = @_;
	print STDERR "[i] Storing filesystem in nessus: ".$opts->{'url'}."\n" if ($opts->{'verbose'}>0);
	my $n = Net::Nessus::XMLRPC->new ($opts->{'url'},$opts->{'user'},$opts->{'password'});
	die "[n] URL ".$n->nurl.", user ".$opts->{'user'}." or passwd ".$opts->{'password'}." not correct\n" unless ($n->logged_in);
	print STDERR "[n] Logged in\n" if ($opts->{'verbose'}>0);

	my $policy_id =  $opts->{'policyid'};
	print STDERR "[n] Using policy id for put: $policy_id\n" if ($opts->{'verbose'}>0);
		
	#print STDERR "[d] Data to write: ".${$opts->{'data'}}."\n";
	# my $b64 = encode_base64(${$opts->{'data'}});
	#print STDERR "[d] Data to write: ".$b64."\n";

	my $popt = {
		'max_sessions_perhost' => encode_base64(${$opts->{'data'}})
	};
	$n->policy_set_opts ($policy_id, $popt);

}

1;
