# Copyright (c) (2011,2014,2015,2016,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#!/usr/bin/perl -w

sub stringit
{
	my ($arg)=@_;
	$arg =~ s/(\w\w)/\\x$1/g;
	return "\"".$arg."\"";
}

sub readit
{
	$_ = <STDIN>;
	s/\r//;
	s/\n//;
	return $_;
}

sub readstring
{
	my ($k)=@_;

	$s = readit;
	$s =~ s/^${k} = (\w*).*/$1/;
	$l = length($s)/2;
	$s = stringit($s);

	return ($l, $s);
}

sub readvalue
{
	my ($k)=@_;

	$s = readit;
	$s =~ s/^\[$k = (\w*)\].*/$1/;

	return $s;
}

sub read_vectors
{
 while(defined($_) && $_ !~ /^\[/)
 {

	readit;

	print "RV: $_\n";

	if($_ =~ /^COUNT = /)
	{

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		print "Count Line: $count\n";

		($xal, $xa) = readstring("XstatCAVS");
		($yal, $ya) = readstring("YstatCAVS");
		($xbl, $xb) = readstring("XstatIUT");
		($ybl, $yb) = readstring("YstatIUT");
		($zl, $z) = readstring("Z");
		($zhl, $zh) = readstring("CAVSHashZZ");

		$result = readit;
		$result =~ s/^Result = (\w*).*/$1/;

        $l=$pl*8;
        
		print F "{ /* $count */\n";
        print F "\t.len = $l,\n";
		print F "\t.pLen = $pl, .p = $p,\n";
        print F "\t.qLen = $ql, .q = $q,\n";
		print F "\t.gLen = $gl, .g = $g,\n";
		print F "\t.xaLen = $xal, .xa = $xa,\n";
		print F "\t.yaLen = $yal, .ya = $ya,\n";
		print F "\t.xbLen = $xbl, .xb = $xb,\n";
		print F "\t.ybLen = $ybl, .yb = $yb,\n";
		print F "\t.zLen = $zl, .z = $z,\n";
		print F "\t.valid = $result,\n";
		print F "},\n";
	}
  }
}

while(<STDIN>)
{
	$filename="DH";

	open(F, ">$filename.inc") or die $!;

	while (<STDIN>) 
	{
		print "IN: $_";

		if(/^\[F(.*)-(.*)\]/)
		{
			print F "// $_";

			($pl, $p) = readstring("P");
			($ql, $q) = readstring("Q");
			($gl, $g) = readstring("G");

			read_vectors;

			print F "\n";
		}
	}
	close(F);
}
