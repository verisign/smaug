The software and code contained herein has absolutely no guarantee written or implied.
USE AT YOUR OWN RISK !!!

SMAUG
==========

The software in this repository has been constructed to serve as a proof of concept for DANE/Smime body of works under discussion.

This prototype is tested on Red Hat Linux 6 and Mac OSX Version 10.9.

The origin of the work draws from DANE/TLS RFC:

	RFC 6698   https://tools.ietf.org/html/rfc6698

The work currently implents a specific set of changes proposed by SRose for the original 02 version found at http://tools.ietf.org/html/draft-ietf-dane-smime-02.  A version with the proposed changes exists in docs directory.  

Additionally, we have adopted the use of sha\_224 encoding for the left-hand side of the email address.

Compiling
===========

dane-smime.xpi:

This is the Thuderbird extension.

Thunderbird Extension Installation
===================================
Dependency: getDns library must be installed ( https://getdnsapi.net/doc.html ) 
Dependency: Thunderbird 24 (version tested)

1. Check out the full dane-email repository
2. compile

<code>
git clone <repository>
<br>
cd Smaug
<br>
make
</code>

A build directory will be constructed containing the libdane shared library and the dane-smime.xpi thunderbird
extension.  The library must be included in the normal library path or referenced by LD\_LIBRARY\_PATH on Linux/unix systems.

For Example, you could install it globally for your system, assuing sudo privileges:
<code>
sudo cp libdane.\* /usr/local/lib
<br>
export LD\_LIBRARY\_PATH=$LD\_LIBRARY\_PATH:/usr/local/lib
<br>
</code>

launch thunderbird
add-extension from file, and select the .xpi file
it should say ok, and then prompt to restart thunderbird.

now go to the icon bar, right click to customize, and add the dane decrypt button by dragging it from the dialog to the toolbar.
now click the write button to compose a message, and right click on the toolbar.  Drag the dane-encrypt button to the toolbar.

You should now be ready to go.

FOR DEVELOPERS:
===============
Sample Code:
In the src directory, there are a couple of programs that can be used as references.

domain\_socket\_srv, domain\_socket\_client, domain\_client\_test
These two files creat a client and server over a domain socket.  The domain\_client\_test is used to test the protocol
with a public key.  Attempting to use a large key with the domain\_socket\_client fails on some platforms, such as on the Mac.

hash\_test <string>
Simply provide the sha224 hash of a given string.  For phrases, simply quote the phrase on the command line, ie
./hash\_test "foo bar"

test\_dane\_email <email address>
Will perform a dns lookup for both an encryption key and a signing key and display the results


Thunderbird Development
=======================
I have left a few notes and readme files in the extensions directory and subdirectories as references for developing Mozilla extensions.

If you would like to build on the current extensions, I suggest that you reference the information here about a proxy file.  Using a proxy file will save you countless steps for testing your changes.
See extension proxy file:
https://developer.mozilla.org/en-US/Add-ons/Setting\_up\_extension\_development\_environment
