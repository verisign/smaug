The software and code contained herein has absolutely no guarantee written or implied.
USE AT YOUR OWN RISK !!!

SMAUG
==========

The software in this repository builds a library to implement protocols based on DNS-based Authentication of Named
Entities (DANE), an IETF working group:
  https://datatracker.ietf.org/wg/dane/charter/

This library has been constructed to serve as a proof of concept for
multiple DANE-based protocols.  Currently, the implementation implements simple
S/MIME capabilities using DANE.


Dependencies
======

To compile Smaug, there are several mandatory dependencies, and a few optional packages which can be 
enabled, and result in further dependencies.

Smaug depends on OpenSSL and libunbound.  Optionally, Smaug can be configured to use the getdns API by using the
configure option:
``./configure --enable-getdns
``
This option requires the installation of libgetdns, and its dependencies.

To install the mandatory dependencies:

Redhat/CentOS/Fedora
----

```
sudo yum install unbound-devel
sudo install openssl-devel
```

Mac OS X
---

```
sudo port install openssl
# cd to a build directory
wget http://www.unbound.net/downloads/unbound-latest.tar.gz
tar -xf unbound-latest.tar.gz
cd unbound-[0-9]*
./configure && make && sudo make install
```

Ubuntu / Debian
---

```
apt-get install libunbound-dev
apt-get install libssl-dev
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

After compliation, several test drivers will be left in the source directory.  In addition to installing the
reference library in the &quot;$(prefix)/lib&quot; directory, the command-line utility

 ```
smimeagen
```

Will be installed in &quot;$(prefix)/bin&quot;.  This utility will help create SMIMEA records, in a format suitable
for being pasted into a DNS zone file.

If an S/MIME certificate is needed, there is a convienent S/MIME certificate generation script to help:

```
<smaug repo>/scripts/smime-gen.sh
```


Example Code
===========


