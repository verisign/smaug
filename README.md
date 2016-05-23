![Logo](pix/smaug.png "Logo")

What is libsmaug?
==========

Smaug is a C++ library that implements the growing set of
DNS-based Authentication of Named Entities (DANE) protocols specified
by the IETF working group: https://datatracker.ietf.org/wg/dane/charter/

Smaug is a reference implementation of DANE,
and currently implements all of DANE's S/MIME capabilities (SMIMEA), 
its Open PGP capabilities (OPENPGPKEY), and has scripts to easily generate
S/MIME certificates, and TLSA records (though it does not implement a secure
sockets layer for TLS).

The specific features supported are described in the [Release
Notes](./ReleaseNotes.md)

Authored by Eric Osterweil eosterweil@verisign.com and Glen Wiley gwiley@verisign.com

Also see Smaug's [Thunderbird plugin](https://github.com/verisign/smaug-tbird-plugin).

# Table of Contents

* [Compiling](#compiling)
* [Dependencies](#dependencies)
* [Executables](#executables)
* [Example Code](#examples)
* [Why libsmaug?](#why)


#<a name="compiling"></a>
Compiling libsmaug
===========

```
autoreconf -ivf
./configure
make
sudo make install
```

Make sure that the DNSSEC root KSK (or trust anchor) is installed.  This can be done by running the utility

```sudo unbound-anchor ```

This utility is part of the unbound development suite.


#<a name="dependencies"></a>
Dependencies
======

To compile Smaug, there are several mandatory dependencies, and a few
optional packages which can be enabled, and result in further
dependencies.

Smaug depends on OpenSSL and libunbound.  Optionally, Smaug can be
configured to use the getdns API by using the configure option:
``./configure --enable-getdns ``
This option requires the installation of libgetdns, and its
dependencies.

This beta library is mainly being tested on OS X (and likely works on Linux too).

To install the mandatory dependencies:

Redhat/CentOS/Fedora
----

```
sudo yum install automake
sudo yum install libtool
sudo yum install unbound-devel
sudo install openssl-devel
sudo install gpgme-devel
```

Mac OS X
---
If you use ports:
```
sudo port install automake
sudo port install libtool
sudo port install openssl
sudo port install gpgme-devel
# cd to a build directory
wget http://www.unbound.net/downloads/unbound-latest.tar.gz
tar -xf unbound-latest.tar.gz
cd unbound-[0-9]*
./configure --with-libunbound-only 
make 
sudo make install
sudo make install unbound-anchor
```

If you use brew:

Note that some of the tools will end up with a "g"
prefix to avoid conflicts with Apple's tool chain.

```
brew install automake
brew install libtool
```

The brew version of openssl at the time of this writing might
be missing some symbols that we need, so in these instructions
we pull openssl sources and build them to satisfy that dependency.
The ones delivered with OSX are helpful at trying to motivate you 
to use something else but less helpful at getting our stuff built.

```
git clone https://github.com/openssl/openssl
git checkout -b OpenSSL_1_0_2
cd openssl
./Configure darwin64-x86_64-cc
make
```

Finally, we build libunbound:

```
wget http://www.unbound.net/downloads/unbound-latest.tar.gz
tar -xf unbound-latest.tar.gz
cd unbound-[0-9]*
./configure --with-libunbound-only
make
sudo make install
sudo make install unbound-anchor
```

In case you didn't know, trying to use both ports and brew is like
"crossing the streams" - don't do it.

Ubuntu / Debian
---

```
sudo apt-get install automake
sudo apt-get install libtool
sudo apt-get install libunbound-dev
sudo apt-get install libssl-dev
sudo apt-get install gpgme-devel
```


#<a name="exectuables"></a>
Executables
===========

After compilation, several test drivers will be left in the source directory.
In addition to installing the reference library in the
&quot;$(prefix)/lib&quot; directory, the command-line utilities:

 ```
smimeagen
```

This utility will be installed in &quot;$(prefix)/bin&quot;, and it will help create
SMIMEA records in a format suitable for being pasted into a DNS zone file.

If an S/MIME certificate is needed, there is a convenient S/MIME certificate
generation script that gets installed, which will prompt you for your data:

```
smime-gen.sh
```

The script writes the files to the ~/sssmime directory.  The file 
with a "-combined.pem" suffix can be used to feed the test_smg_smime_cert
test program and other programs that need the certificate in ASCII PEM format.

and

```
openpgpkeygen
```

This utility will be installed in &quot;$(prefix)/bin&quot;, and it will help create
OPENPGPKEY records in a format suitable for being pasted into a DNS zone file.

and

```
tlsagen
```

This utility will be installed in &quot;$(prefix)/bin&quot;, and it will help create
TLSA records in a format suitable for being pasted into a DNS zone file.


#<a name="examples"></a>
Example Code
===========

Simple S/MIME encryption certificate lookup
----

```
#include <string>

#include <smg_net.h>
#include <smg_id.h>
#include <smg_smime_association.h>

int main(int argc, char *argv[]) {
  std::string sName = "user@example.com";

  SmgNet oNet;
  SmgID oID;

  if (!oNet.init()) {
    fprintf(stderr, "Could not init network layer.\n");
  }
  else if (!oID.init(sName)) {
    fprintf(stderr, "Could not init ID object.\n");
  }
  else if (!oNet.lookupID(oID, ACT_ENCR)) {
    fprintf(stderr, "Unable to lookup ID for encryption.\n");
  }
  else
  {
    // Loop over the respons(es)
    SmgSmimeAssocKIter_t tIter;
    for (tIter = oID.beginEncAssociations();
         oID.endEncAssociations() != tIter;
         tIter++) {
      std::string sTxt;
      (*tIter)->toText(sTxt);
      fprintf(stdout, "\t%s\n", sTxt.c_str());
    }
  }

  return 0;
}
```

#<a name="why"></a>
BECAUSE: TRUE INTERNET-SCALE OBJECT SECURITY
===========

We have a problem with security in the Internet today, and it's not new.  Before we can encrypt data or verify signatures, we need a way for someone bootstrap and learn what cryptographic keys are needed.  Our security protocols have not formally specified a standardized way to securely bootstrap protocols, until now.

Recently, however, a simple observation has sparked a flurry of innovation: for those protocols that use DNS, secure key learning can be accomplished from DNS itself, and verified by the DNS Security Extensions (DNSSEC).  The IETF has started standardizing a suite of protocols called DNS-based Authentication of Named Entities [DANE](https://datatracker.ietf.org/wg/dane/charter/) to do secure key learning in a general way for Internet services.  

This library (Smaug) is a general object security library that uses S/MIME to offer object security primitives using DANE S/MIME.

