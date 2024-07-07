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
 while($_ !~ /^\[/)
 {
	readit;

	if($_ =~ /^COUNT = /)
	{
		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		($el, $e) = readstring("EntropyInput");
		($nl, $n) = readstring("Nonce");
		($psl, $ps) = readstring("PersonalizationString");
		
		readit;	# skip ** INSTANTIATE:
		readit; # skip 	    V   = ...
		readit; # skip 		Key = 

		($erl, $er) = readstring("EntropyInputReseed");
		($arl, $ar) = readstring("AdditionalInputReseed");
		
		readit;	# skip ** RESEED:
		readit; # skip 	    V   = ...
		readit; # skip 		Key = 
		
		($a0l, $a0) = readstring("AdditionalInput");

		readit;	# skip ** GENERATE (FIRST CALL):
		readit; # skip 	    V   = ...
		readit; # skip 		Key = 
		
		($a1l, $a1) = readstring("AdditionalInput");

		($rl, $r) = readstring("ReturnedBits");

		readit;	# skip ** GENERATE (SECOND CALL):
		readit; # skip 	    V   = ...
		readit; # skip 		Key = 
		
		print F "{ /* $count */\n";
		print F "\t$el, $e,\n";
		print F "\t$nl, $n,\n";
		print F "\t$psl, $ps,\n";
		print F "\t$a0l, $a0,\n";
		print F "\t$erl, $er,\n";
		print F "\t$arl, $ar,\n";
		print F "\t$a1l, $a1,\n";
		print F "\t$rl, $r\n";
		print F "},\n";
	}
  }
}


sub read_vectors_PR
{

 while($_ !~ /^\[/) {

	readit;

	if($_ =~ /^COUNT = /)
	{

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

		($el, $e) = readstring("EntropyInput");
		($nl, $n) = readstring("Nonce");
		($psl, $ps) = readstring("PersonalizationString");
		($a0l, $a0) = readstring("AdditionalInput");
		($e1l, $e1) = readstring("EntropyInputPR");
		($a1l, $a1) = readstring("AdditionalInput");
		($e2l, $e2) = readstring("EntropyInputPR");
		($rl, $r) = readstring("ReturnedBits");

		print F "{ /* $count */\n";
		print F "\t$el, $e,\n";
		print F "\t$nl, $n,\n";
		print F "\t$psl, $ps,\n";
		print F "\t$a0l, $a0,\n";
		print F "\t$e1l, $e1,\n";
		print F "\t$a1l, $a1,\n";
		print F "\t$e2l, $e2,\n";
		print F "\t$rl, $r\n";
		print F "},\n";
	}
  }
}
 
while(<STDIN>)
{
	if (/^\[(SHA-[^]]*)/)
	{
		$cipher = $1;
		$cipher =~ s|/|-|g;		# Fix so that SHA-224/512 doesn't make a bad filename
		
		$PR = readvalue("PredictionResistance");
		$EIL = readvalue("EntropyInputLen");
		$NL = readvalue("NonceLen");
		$PSL = readvalue("PersonalizationStringLen");
		$AIL = readvalue("AdditionalInputLen");
		$RBL = readvalue("ReturnedBitsLen");

		readit;

		$filename="HMAC_DRBG-".$cipher;

		if($PR =~ /True/) {
			$filename=$filename."-PR";
		}

		open(F, ">>$filename.inc");

		print F "/* Cipher: $cipher ";
		print F " PR: $PR ";
		print F " EIL: $EIL ";
		print F " NL: $NL ";
		print F " PSL: $PSL ";
		print F " AIL: $AIL ";
		print F " RBL: $RBL */\n";

		if($PR =~ /True/) {
			read_vectors_PR;
		} else {
			read_vectors;
		}

		print F "\n";

		close(F);
	}
}
