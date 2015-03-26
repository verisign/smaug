TRUE INTERNET-SCALE OBJECT SECURITY
===========

We have a problem with security in the Internet today, and it's not new.  Before we can encrypt data or 
verify signatures, we need a way for someone bootstrap and learn what cryptographic keys are needed.  
Our security protocols have not formally specified a standardized way to securely bootstrap protocols, until now.

Recently, however, a simple observation has sparked a flurry of innovation: for those protocols that use DNS,
secure key learning can be accomplished from DNS itself, and verified by the DNS Security Extensions (DNSSEC).
The IETF has started standardizing a suite of protocols called DNS-based Authentication of Named Entities
[DANE](https://datatracker.ietf.org/wg/dane/charter/) to do secure key learning in a general way for 
Internet services.  

This library (Smaug) is a general object security library that uses S/MIME to offer object 
security primitves using DANE S/MIME.

SMAUG
==========

The software in this repository builds a library to implement
protocols based on DNS-based Authentication of Named Entities (DANE),
an IETF working group: https://datatracker.ietf.org/wg/dane/charter/

This library has been constructed to serve as a proof of concept for
multiple DANE-based protocols.  Currently, the implementation
implements simple S/MIME capabilities using DANE.

The specific features supported are described in teh [Release
Notes](./ReleaseNotes.md)

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

To install the mandatory dependencies:

Redhat/CentOS/Fedora
----

```
sudo yum install automake
sudo yum install libtool
sudo yum install unbound-devel
sudo install openssl-devel
```

Mac OS X
---
If you use ports:
```
sudo port install automake
sudo port install libtool
sudo port install openssl
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
```


Compiling libsmaug
===========

```
autoreconf -i
./configure
make
sudo make install
```

Make sure that the DNSSEC root KSK (or trust anchor) is installed.  This can be done by running the utility

```sudo unbound-anchor ```

This utility is part of the unbound development suite.

Executables
===========

After compliation, several test drivers will be left in the source directory.
In addition to installing the reference library in the
&quot;$(prefix)/lib&quot; directory, the command-line utility

 ```
smimeagen
```

Will be installed in &quot;$(prefix)/bin&quot;.  This utility will help create
SMIMEA records, in a format suitable for being pasted into a DNS zone file.

If an S/MIME certificate is needed, there is a convienent S/MIME certificate
generation script that will prompt you for your data:

```
<smaug repo>/scripts/smime-gen.sh
```

The script writes the files to the ~/sssmime directory.  The file 
with a "-combined.pem" suffix can be used to feed the test_smg_smime_cert
test program and other programs that need the certificate in ASCII PEM format.

Example Code
===========

Simple encryption certificate lookup
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
      string sTxt;
      (*tIter)->toText(sTxt);
      fprintf(stdout, "\t%s\n", sTxt.c_str());
    }
  }

  return 0;
}
