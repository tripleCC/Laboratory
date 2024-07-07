# Copyright (c) (2016,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#!/usr/bin/perl -w

#myfile=CMACVerAES128.rsp ; cat $myfile | perl cmac.pl > "${myfile%.*}".inc

sub stringit
{
	my ($arg)=@_;
#	$arg =~ s/(\w\w)/\\x$1/g;
	return "\"".$arg."\"";
}

sub readit
{
	$_ = <STDIN>;
	s/\r//;
	s/\n//;
	return $_;
}

sub readinteger
{
    my ($k)=@_;

    $lv = readit;
    $lv =~ s/^${k} = (\w*).*/$1/;

    return $lv
}

sub readstring
{
    my ($k)=@_[0];
    my ($l)=@_[1];

    $s = readit;
    $s =~ s/^${k} = (\w*).*/$1/;
    if ($l eq 0) {
        $s = "";
    }
    $l = ".${k}_len = " . length($s)/2;
    $s = ".${k} = " . stringit($s);

    return ($l, $s);
}

while(<STDIN>)
{

	if(/^\[L=(\w*)\]/) {
		$L = $1;
	}

	if($_ =~ /^Count = /) {

		$count = $_;
		$count =~ s/\r//;
		$count =~ s/\n//;

        $kl = readinteger("Klen");
        $ml = readinteger("Mlen");
		$tl = readinteger("Tlen");

        ($keyl, $key) = readstring("Key",$kl);
        ($msgl, $msg) = readstring("Msg",$ml);
        ($macl, $mac) = readstring("Mac",$tl);

		$res = readit;
		$res =~ s/^Result = (\w*)/.Result = $1 /;
		$res =~ s/\(/\/\* Expect error: /;
		$res =~ s/\)/ \*\//;
		$res =~ s/ F / -1 /;
		$res =~ s/ P / 0 /;
		if ($res eq '') {
  			$res = '.Result =  0';
		}

		print "{\t.$count,\n";
        print "\t$keyl,\n\t$key,\n";
        print "\t$msgl,\n\t$msg,\n";
        print "\t$macl,\n\t$mac,\n";
        print "\t$res\n";
		print "},\n";
	}

}
