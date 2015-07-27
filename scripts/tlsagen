#!/usr/bin/perl -w

use strict;

sub _usage
{
  print("tlsagen.pl <domain name> <usage> <selector> <matching> <cert file> | -h\n");
}

my $sDomain = shift;
my $iUsg = shift;
my $iSel = shift;
my $iMat = shift;
my $sFile = shift;

if (!defined($sDomain))
{
  warn("Domain name not specified");
  _usage();
}
elsif ("-h" eq $sDomain)
{
  _usage();
}
elsif (!defined($iUsg))
{
  warn("Usage not defined");
  _usage();
}
elsif (!defined($iSel))
{
  warn("Selector not defined");
  _usage();
}
elsif (!defined($iMat))
{
  warn("Matching not defined");
  _usage();
}
elsif (!defined($sFile))
{
  warn("Cert file not defined");
  _usage();
}
elsif ($iUsg !~ /^\d+$/)
{
  warn("Usage is not a whole number: $iUsg");
  _usage();
}
elsif ($iSel !~ /^\d+$/)
{
  warn("Selector is not a whole number: $iSel");
  _usage();
} 
elsif ($iMat !~ /^\d+$/)
{
  warn("Matching is not a whole number: $iMat");
}
else
{
  my $bOK = 0;

  my $sHash = "";
  if (1 == $iMat)
  {
    $sHash = " openssl dgst -sha256 -binary |";
  }
  elsif (2 == $iMat)
  {
    $sHash = " openssl dgst -sha512 -binary |";
  }

  if (0 == $iSel)
  {
    if (!open(CERT, "openssl x509 -inform PEM -outform DER -in $sFile | $sHash"))
    {
      warn("Unable to process file '$sFile': $!");
    }
    else
    {
      $bOK = 1;
    }
  }
  elsif (1 == $iSel)
  {
    if (!open(CERT, "openssl x509 -in $sFile -pubkey -noout | openssl rsa -pubin -outform der | $sHash"))
    {
      warn("Unable to process file '$sFile': $!");
    }
    else
    {
      $bOK = 1;
    }
  }
  else
  {
    warn("Unrecognized selector value '$iSel'");
  }

  if ($bOK)
  {
    binmode(CERT);

    $sDomain .= ($sDomain !~ /\.$/) ? "." : "";
    my $sOut = "$sDomain IN TLSA $iUsg $iSel $iMat ";

    my $sTmp;
    my $pBuff;
    while (read(CERT, $pBuff, 2) != 0)
    {
      $sOut .= sprintf("%02x", ord($pBuff));
    }
    close(CERT);

    print($sOut, "\n");
  }
}
