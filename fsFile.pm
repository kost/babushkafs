#!/usr/bin/perl

package fsFile;

use File::Slurp;

sub getdata {
	my ($opts) = @_;
	print STDERR "[i] Getting filesystem from file: ".$opts->{'filename'}."\n" if ($opts->{'verbose'}>0);
	my $file = read_file($opts->{'filename'});
	return $file;
}

sub putdata {
my ($opts) = @_;
	print STDERR "[i] Storing filesystem in file: ".$opts->{'filename'}."\n" if ($opts->{'verbose'}>0);
	open (FILE, ">".$opts->{'filename'}) or die ("cannot open file: $!");
	print FILE ${$opts->{'data'}};
	close (FILE);
}

1;
