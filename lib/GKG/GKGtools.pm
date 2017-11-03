package GKG::GKGtools;

use HTTP::Request;
use LWP::UserAgent;
use Net::DNS::RR;
use JSON::XS;
use POSIX;
use strict;
use warnings;
require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use GKG::GKGtools ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw($gkg_conffile $admin $enforcer
) ] );

our @EXPORT_OK = qw(readconf get_keys write_dsrec get_whois delete_old_key parse_dnskey $gkg_conffile $admin $enforcer);


our $VERSION = '0.02';

our $gkg_conffile = "/etc/gkg.conf";
our $maxsiglife = 3456000;
our $enforcer = "/usr/local/sbin/ods-enforcer";
our $admin = "root";

# Preloaded methods go here.
sub readconf {
    my $gotu=0;
    my $gotp=0;
    my $username;
    my $password;
    my @l;

 
 
    if ( $#ARGV > -1 ) {
	if ( $ARGV[0] eq "-c" ) {
	    shift @ARGV;
	    $gkg_conffile=shift(@ARGV);
	}
    }
 
    open(C,$gkg_conffile) ||die "$0: $!";

# parse username and password.

    while (  ! eof(C) ) {
	$_=<C>;
	chomp;
	@l=split(/=/);
	my $cmd= lc($l[0]);
	if ( $cmd !~ /^(username|password|maxsiglife|admin|enforcer)/) {
	    print "$0: Unrecognized command $cmd in $gkg_conffile\n";
	    next;
	}
	    
	if ( $cmd eq "username" ) {
	    $username=$l[1];
	    $gotu=1;
	    next;
	}
	if ( $cmd eq "password" ) {
	    $password=$l[1];
	    $gotp=1;
	    next;
	}
	if ( $cmd eq "maxsiglife" ) {
	    if ( $l[1] =~ /^\d+$/ ) {
		$maxsiglife=$l[1];
	    } else {
		print "$0: bad value for maxsiglife: " . $l[1] . "\n";
	    }
	    next;
	}
	if ( $cmd eq "admin" ) {
	    $admin=$l[1];
	    next;
	}
	if ( $cmd eq "enforcer" ) {
	    $enforcer=$l[1];
	    next;
	}
    }

    if ( $gotu == 0 || $gotp == 0) {
	print( "no username or password\n");
	return("","");
    } else {
	return($username,$password);
    }
}


# read JSON into an array

sub get_keys {
    my $domain=shift(@_);	# domain name
    my $username=shift(@_);
    my $password=shift(@_);
    my $uri= "https://www.gkg.net/ws/domain/" . $domain . "/ds"; # post uri
    my $req= HTTP::Request->new('GET', $uri );	     # construct request
    $req->header("Accept" => "application/json");
    my $lwp= LWP::UserAgent->new;
    $req->authorization_basic($username,$password);
    my $response=$lwp->request($req); # execute request
    if ($response->code ne "200") { # 201 indicates success.
	if ( $response->code eq "404" ) { # 404 means no records
	    return undef;		  # it's not fatal.
	}
	print "get_keys: GET $uri" . ": " . $response->message . "\n" ; # more serious
	return undef;
    }
    return decode_json($response->content);
}

# get a whois record.
sub get_whois {
    my $domain=shift(@_);	# domain name
    my $username=shift(@_);
    my $password=shift(@_);
    my $uri= "https://www.gkg.net/ws/domain/" . $domain . "/whois"; # post uri
    my $req= HTTP::Request->new('GET', $uri );	     # construct request
#    $req->header("Accept" => "application/json");
    my $lwp= LWP::UserAgent->new;
    $req->authorization_basic($username,$password);
    my $response=$lwp->request($req); # execute request
    if ($response->code ne "200" ||
	$response->content =~ /No match for.*/ ) { 
#	print "$domain not served by GKG:" .  $response->content;
	return -1;	      # not our registrar!
    }
    return 0;
}

#
# post_request
# takes as arguments:
#  domainname, json, username, password
#
#  returns 0 on success, -1 on failure.
#  Side effects: prints error message.

sub post_request {
    my $response;
    my $domain=shift(@_);	# domain name
    my $j=shift(@_);		# here's the json.
    my $username=shift(@_);
    my $password=shift(@_);
    my $uri= "https://www.gkg.net/ws/domain/" . $domain . "/ds"; # post uri
    my $req= HTTP::Request->new('POST', $uri );	     # construct request
    $req->header("Accept" => "application/json");
    $req->header("Content-type" => "application/json");
    my $lwp= LWP::UserAgent->new;
    $req->authorization_basic($username,$password);
    $req->content($j);
    $response=$lwp->request($req); # execute request
    if ($response->code ne "201") { # 201 indicates success.
	print "post_request: $uri" . ": " . $response->message . "\n" ;
	return -1;
    }
    return 0;
}

# make the json content that needs to be passed with the request.

# takes as as arguments:
# domain, keytag, algorithm, digest type, digest
# returns: a json string.

sub mkjson {
    my $drec=shift(@_);

    my $domain=$drec->{domain};
    my $keytag=$drec->{keytag};
    my $alg=$drec->{alg};
    my $digtype=$drec->{digtype};
    my $digest=$drec->{digest};

    my $jstring='{' . "\n" . 
	'"digest":"' . $digest . "\",\n" .
	'"digestType":"' . $digtype . '",' . "\n" .
	'"algorithm":"' . $alg . '",' . "\n" .
        '"keyTag":"' . $keytag . '",' . "\n" .
	'"maxSigLife": "' . $maxsiglife . '"' . "\n}\n" ;
    return $jstring;
}

# Takes as input an a domain name and a string.
# Returns an array of a key information used later.

sub to_dnsrec {
    my $n=shift(@_);
    my $l = shift(@_);
    $l =~ s/\n/ /g; # join lines
    $l =~ s/[()]//g; # get rid of parentheses
    my @drec=split(/\s+/,$l);
    my $domain=$drec[0];
    my $keytag=$drec[4];
    my $alg=$drec[5];
    my $digtype=$drec[6];
    my $digest=$drec[7];
    $digest =~ tr/a-z/A-Z/; # convert to upper case
    
    return ({ rrdn => $n, domain => $domain, keytag => $keytag, alg => $alg,
	    digtype => $digtype, digest => $digest} );
}

sub parse_dnskey {
    my $in=shift(@_);
    my @drec;
    if ( !eof($in) ) {     # Take as input a DNSKEY record
	$_=<$in>;
	chomp;
	if ( (! ( /^[\s]*;.*/ || /^$/ || /^[\s]*$/ )) && (  /.*DNSKEY.*/ ) ) {
	    my $rr= new Net::DNS::RR($_);		# exits on error
	    my $ds_sha1rr=create Net::DNS::RR::DS($rr); # only thing we have
	    my $ds_sha256rr=create Net::DNS::RR::DS($rr, digtype=>"SHA256");
	    push @drec, to_dnsrec($rr->name,$ds_sha1rr->string);
	    push @drec, to_dnsrec($rr->name,$ds_sha256rr->string);
	}
    }
    return (@drec);
}

# write a DS record to GKG.NET.

sub write_dsrec {
    my $username=shift(@_);
    my $password=shift(@_);
    my @drec=@_;
    my $err=0;
    my $i;
    my $j;

    for ($i=0;$i<=$#drec;$i=$i+1) {
	if ( ! exists($drec[$i]->{"ignore"}) ) {
	    my $j=mkjson($drec[$i]);
	    return -1 if post_request($drec[$i]->{"rrdn"},$j,$username,$password) == -1;
	} else {
	    print "ignoring " . $drec[$i]->{"keytag"} . "\n";
	    $err=-1;
	}
    }
    return 0;
}

sub delete_old_key {
    my $response;
    my $domain=shift(@_);	# domain name
    my $digest=shift(@_);		
    my $username=shift(@_);
    my $password=shift(@_);
    my $uri= "https://www.gkg.net/ws/domain/" . $domain . "/ds/" .
	$digest; # delete uri
    my $req= HTTP::Request->new('DELETE', $uri );	     # construct request
    $req->header("Accept" => "application/json");
    my $lwp= LWP::UserAgent->new;
    $req->authorization_basic($username,$password);
    $response=$lwp->request($req); # execute request
    if ($response->code ne "204") { # 204 indicates success.
	print "delete_old_key: $uri" . ": " . $response->message . "\n" ;
	return -1;
    }
    return 0;
}

1;
__END__

# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

GKG::GKGtools - Perl library functions for GKG.NET RESTful interface

=head1 SYNOPSIS

  use GKG::GKGtools;


=head1 DESCRIPTION

This module makes available several routines that facilitate manipulation
of DS records on GKG.NET.  The key ones are as follows:

=head2 GKGtools::readconf

This routine reads the username, password, and optionally maxsiglife
used to call out to GKG.NET.  These are stored in a file:
/etc/gkg.conf.

It takes the following form:

  username=yournamehere
  password=secrethere
  maxsiglife=nnnnn (integer time in seconds)


If maxsiglife is ommitted, a value of 3456000 is used.

=head2 GKGtools::get_keys

takes as an argument a domain, username, and password, and returns a
decoded JSON response.

=head GKGtools::write_dsrec($username, $password, @drec)

This function writes to GKG DS records.  It takes as argument
$username, $password, and a record that his the following entries:

   rrdn: the RR domain name
   domain: similar (this may be removed later)
   keytag: the key tag of the record to be installed
   alg: algorithm number in play
   digtype: digest type
   digest: the value of the digest to be set.

It returns -1 on failure or 0 on success.

=head GKGtools::delete_old_key($domain, $digest, $username, $password)

This routine deletes a key from GKG.NET given all of the above.  It
returns -1 on failure and 0 on success. It also will output any error
message returned from GKG.NET.


=head2 EXPORT

bunches of stuff for use by the GKG.NET programs.


=head1 SEE ALSO

https://www.gkg.net/ws/ds.html

=head1 AUTHOR

Eliot Lear, <lt>lear@ofcourseimright.com<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 by Eliot Lear

All rights reserved.

 WARNING WARNING WARNING WARNING WARNING WARNING WARNING

  EARLY CODE.  This code can and will change, and it should change.
  Don't use on important domains YET.
  
 WARNING WARNING WARNING WARNING WARNING WARNING WARNING

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

=cut
