#!/bin/perl
#modules
#use File::Monitor;
use strict;
use Digest::MD5;
#Variables

my $file_alerts;
my $arreglo=();
#my $monitor = File::Monitor->new;
my $actualmd5;
my $md5mod;
my $networks="extif=\"vic0\"\nintif=\"vic1\"\n";
my $attacker;
my $webServer;
my $port;

lectura();

sub md5sum{
  my $file = $ARGV[0];
  my $digest = "";
  eval{
    open(FILE, $file) or die "No se puede encontrar el archivo $file\n";
    my $ctx = Digest::MD5->new;
    $ctx->addfile(*FILE);
    $digest = $ctx->hexdigest;
    close(FILE);
  };
  if($@){
    print $@;
    return "";
  }
  return $digest;
}



sub lectura{
	if (-f $ARGV[0]){
   		print "Dentro del if\n";
   		 $actualmd5=md5sum();
   		 print "$actualmd5 ";
   		 while(1){
   		 	$md5mod=md5sum();
   		 	print "$md5mod";
   		 	if ($actualmd5 != $md5mod){
   		 		print " El archivo ha cambiado\n";
   		 		writes();
   		 		last;
   		 	}else{
   		 		print " No ha cambiado\n";
   		 	}
   		 	#sleep (1);
   		 }
		
	}else{
	usage();
	}
}
sub usage{
	print "perl $0 log_monitoreo_snort\n";
}

sub writes{
	print "inside write";
	system("tcpdump -nnr $ARGV[0] > NuevaCaptura");
	open(ARCHIVO,'NuevaCaptura') or die "No se pudo abrir el archivo";
	while(<ARCHIVO>){
		chomp($_);
		if($_ =~ m/(([0-9]{1,3}\.){3}[0-9]{1,3})(\.[0-9]+)(\s)(\>)(\s)(([0-9]{1,3}\.){3}[0-9]{1,3})(\.)([0-9]{2})/){
			print "$1\n";
			print "$7\n$10\n";
			$attacker=$1;
			$webServer=$7;
			$port=$10;
	}
}
truncate "/etc/pf.conf",0;
open(PFCONF ,'>> /etc/pf.conf') or die "No se pudo abrir archivo conf";
			#print PFCONF "$networks\nblock all\n";
			print PFCONF "$networks\nblock in quick on \$intif inet proto tcp from $attacker to $webServer port $port flags any\n";
			print PFCONF "block out quick on \$intif inet proto tcp from $attacker to $webServer port $port flags any\n";
			system("pfctl -f /etc/pf.conf -e");
			system("rm -r NuevaCaptura");
			close(PFCONF);
}