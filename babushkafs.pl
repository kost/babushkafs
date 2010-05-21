#!/usr/bin/perl

use strict;

use Fuse::Simple qw(accessor main);
use Errno qw(:POSIX);
use Storable qw(freeze thaw);
use MIME::Base64;
use Crypt::GCrypt;
use Getopt::Long;

# available fs containers
use fsFile;
use fsNessusReports;
use fsNessusPolicies;
my $dcont = { 
	'file' => { get => \&fsFile::getdata, put => \&fsFile::putdata },
	'nessus-reports' => { get => \&fsNessusReports::getdata, put => \&fsNessusReports::putdata },
	'nessus-policies'  => { get => \&fsNessusPolicies::getdata, put => \&fsNessusPolicies::putdata }
	};

my $debugsimple = 0;
my $verbose = 0;
my $createfs = 0;
my $serialized;
my $plugf = 'nessus-policies';
my $plugfo; 
my $plugeo;
my $options;

Getopt::Long::Configure ("bundling");
my $result = GetOptions (
	"h|help" => \&help,
	"n|new" => \$createfs,
	"s|store=s" => \$plugf,
	"S|storeopt=s" => \$plugfo,
	"E|encopt=s" => \$plugeo,
	"v|verbose+"  => \$verbose,	
);

unless ($plugf) { 
	print STDERR "Please specify store\n";
	exit (1);
}

unless ($plugfo) { 
	print STDERR "Please specify store options\n";
	exit (1);
}

unless ($plugeo) { 
	print STDERR "Please specify encryption options. Mainly key and IV!\n";
	exit (1);
}

my ($mountpoint) = "";
$mountpoint = shift(@ARGV) if @ARGV;

unless ($mountpoint) {
	print STDERR "Please specify mount point\n";
	exit (1);
}

my $copts= { verbose => $verbose };
my $eopts= { 
	verbose => $verbose,
	type => 'cipher',
	algorithm => 'aes', 
	mode => 'cbc',
	padding => 'standard',
};

foreach my $pair (split(",",$plugfo)) {
	my ($name, $value) = split("=", $pair);
	$copts->{$name} = $value;
}

foreach my $pair (split(",",$plugeo)) {
	my ($name, $value) = split("=", $pair);
	$eopts->{$name} = $value;
}

print STDERR "[i] Starting filesystem: $plugf\n" if ($verbose>0);

# init crypto
my $fkey = $eopts->{'key'};
my $iv = $eopts->{'iv'};
my $cipher = Crypt::GCrypt->new(
	type => 'cipher',
	algorithm => $eopts->{'algorithm'},
	mode => $eopts->{'mode'},
	padding => 'standard',
);

if ($createfs) { 
	# initialize empty hash
	print STDERR "[i] Initializing new filesystem\n" if ($verbose>0);
	my %empty;
	$serialized=freeze \%empty;
} else {
	# get the encrypted data 
	print STDERR "[i] Fetching filesystem\n" if ($verbose>0);
	my $ciphertext = $dcont->{$plugf}->{'get'} ($copts);
	# ... and decrypt it 
	print STDERR "[i] Decrypting filesystem\n" if ($verbose>0);
	eval {
	$cipher->start('decrypting');
	$cipher->setkey($fkey);
	$cipher->setiv($iv);
	$serialized  = $cipher->decrypt($ciphertext);
	$serialized .= $cipher->finish;
	} or die "[e] Filesystem probably not initialized. Initialize it first with -n";
}

#print STDERR "[d] Decrypted: $serialized\n";
# deserialize/thaw data and prepare for filesystem
print STDERR "[i] DeSerializing filesystem\n" if ($verbose>0);
my $filesystem;
eval {
	$filesystem = thaw($serialized);
} or die "[e] Filesystem probably not initialized. Initialize it first with -n";
$serialized=''; # free some memory

print STDERR "[i] Serving filesystem...\n" if ($verbose>0);

main(
	"mountpoint" => $mountpoint,      
	"debug"      => $debugsimple,           
	"fuse_debug" => 0,           
	"threaded"   => 0,           
	"/"          => $filesystem, 
	"mkdir"	     => \&e_mkdir,
	"rmdir"      => \&e_rmdir,
	"unlink"	=> \&e_unlink,
	"rename"	=> \&e_rename,
	"truncate"	=> \&e_truncate,
	"mknod"		=> \&e_mknod,
	"write"		=> \&e_write,
	"flush"		=> \&e_flush,
	"release"	=> \&e_release,
	"getxattr"	=> \&e_getxattr,
	"setxattr"	=> \&e_setxattr,
);

# user has unmounted the drive, proceed with writting the filesystem
# from RAM to specified container

# serialize/freeze data and prepare for encryption
print STDERR "[i] Serializing filesystem\n" if ($verbose>0);
$serialized = freeze $filesystem;

# encrypt it
print STDERR "[i] Encrypting filesystem\n" if ($verbose>0);
$cipher->start('encrypting');
$cipher->setkey($fkey);
$cipher->setiv($iv);

my $ciphertext  = $cipher->encrypt($serialized);
$ciphertext .= $cipher->finish;
$copts->{'data'}=\$ciphertext;

# store it
print STDERR "[i] Storing filesystem\n" if ($verbose>0);
$dcont->{$plugf}->{'put'} ($copts);

# the end
print STDERR "[i] Stopping filesystem\n" if ($verbose>0);


# helpful subroutines 
sub help 
{
	print "$0: Pluggable filesystem containers.\n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 [-n] <-s store> <-S name=value,name2=value2> <-E key=secret,iv=myiv> <mount-path>\n\n";
	print " -n	create new filesystem\n";
	print " -s <s>	use <s> plugin for storage\n";
	print " -S <s>	set following options for storage plugin\n";
	print " -E <s>	set following options for encryption plugin\n";
	print " -v	verbose\n";
	print " -h	this help message\n";
	print "\n";
	print "Example: $0 -n -s file -S filename=test.file -E key=a,iv=a /tmp\n";
	exit (0);
}

# TODO - ifpossible = symlink, link

sub e_mkdir {
	my ($dir) = shift;
	print STDERR "[d] mkdir: ".$dir."\n" if ($verbose>10);
	my (@paths) = split("/",$dir);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	$lastvar->{$paths[-1]}={};
	return 0;
}

sub e_rmdir {
	my ($dir) = shift;
	print STDERR "[d] rmdir: ".$dir."\n" if ($verbose>10);
	my (@paths) = split("/",$dir);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	if (ref($lastvar->{$paths[-1]}) eq "HASH") {
		delete $lastvar->{$paths[-1]};
	} else {
		return -ENOENT();
	}
	return 0;
}

sub e_unlink {
	my ($dir) = shift;
	print STDERR "[d] rm: ".$dir."\n" if ($verbose>10);
	my (@paths) = split("/",$dir);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	if (ref($lastvar->{$paths[-1]}) eq "") {
		delete $lastvar->{$paths[-1]};
	} else {
		return -ENOENT();
	}
	return 0;
}

sub e_rename {
	my ($old, $new) = @_;
	print STDERR "[d] rename: ".$old."\n" if ($verbose>10);
	my (@opaths) = split("/",$old);
	my $olastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#opaths; $i++) {
		if ($olastvar->{$opaths[$i]}) {
			$olastvar = $olastvar->{$opaths[$i]};
		} else {
			return -ENOENT();
		}
	}
	my (@npaths) = split("/",$new);
	my $nlastvar = $filesystem;
	for ($i=1; $i<$#npaths; $i++) {
		if ($nlastvar->{$npaths[$i]}) {
			$nlastvar = $nlastvar->{$npaths[$i]};
		} else {
			return -ENOENT();
		}
	}
	if (ref($olastvar->{$opaths[-1]}) eq "") {
		$nlastvar->{$npaths[-1]} = $olastvar->{$opaths[-1]};
		delete $olastvar->{$opaths[-1]};
	} else {
		return -ENOENT();
	}
	return 0;
}

sub e_truncate {
	my ($pathname, $noffset) = @_;
	print STDERR "[d] truncate: $pathname $noffset\n" if ($verbose>10);
	my (@paths) = split("/",$pathname);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	if (ref($lastvar->{$paths[-1]}) eq "") {
		# $lastvar->{$paths[-1]}=undef;
		$lastvar->{$paths[-1]}=substr($lastvar->{$paths[-1]},0,$noffset);
	} else {
		return -ENOENT();
	}
	return 0;
}

sub e_mknod {
	my ($pathname, $nmode, $ndev) = @_;
	print STDERR "[d] mknod: $pathname $nmode $ndev\n" if ($verbose>10);
	my (@paths) = split("/",$pathname);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	$lastvar->{$paths[-1]} = '';
	return 0;
}

sub e_write {
	my ($pathname, $buffer, $noffset) = @_;
	my $len=length($buffer);
	print STDERR "[d] write: $pathname $len $noffset\n" if ($verbose>10);
	my (@paths) = split("/",$pathname);
	my $lastvar = $filesystem;
	my $i;
	for ($i=1; $i<$#paths; $i++) {
		if ($lastvar->{$paths[$i]}) {
			$lastvar = $lastvar->{$paths[$i]};
		} else {
			return -ENOENT();
		}
	}
	if (ref($lastvar->{$paths[-1]}) eq "") {
		if (length($lastvar->{$paths[-1]})<$noffset+$len) {
			my $firstpart=substr($lastvar->{$paths[-1]}, 0, $noffset);
			$lastvar->{$paths[-1]}=$firstpart.$buffer;
		} else {
		$lastvar->{$paths[-1]}=substr($lastvar->{$paths[-1]}, $noffset, $len, $buffer);
		}
	} else {
		return -ENOENT();
	}
	return $len;
}

sub e_flush {
	my ($pathname) = shift;
	print STDERR "[d] flush: $pathname\n" if ($verbose>10);
	return 0;
}

sub e_release {
	my ($pathname, $nflags ) = @_;
	print STDERR "[d] release: $pathname $nflags\n" if ($verbose>10);
	return 0;
}

sub e_getxattr {
	my ($pathname, $attribname ) = @_;
	print STDERR "[d] getxattr: $pathname $attribname\n" if ($verbose>10);
	return 0;
}

sub e_setxattr {
	my ($pathname, $aname, $avalue, $nflags ) = shift;
	print STDERR "[d] setxattr: $pathname $aname $avalue $nflags\n" if ($verbose>10);
#	return 0;
	return EOPNOTSUPP;
}

