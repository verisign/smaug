Release notes for Smaug 0.7.0 Alpha

Product: Smaug - a DANE/Smime Prototype
Type:    Library and Thunderbird Extension
Version: 0.7.0 Alpha
Date:    11/26/2014

Team:

Eric Osterweil
Lynch Davis
Gowri Visweswaran

Purpose of this release:

This is the first public release of the prototype written as a proof of concept of the DANE/Smime draft


Platforms Supported:

Mac OSX 10.9
CentOS/Red Hat Linux 6.x


Known dependencies of this release:

getdns version 1.5 and its dependencies
openssl-1.0.1j
Thunderbird 31.2.0


Features Supported:

The following outlines the current status of the implementation for the Smaug Alpha 0.7.0
per the DANE SMIMEA draft.

The Certificate Usage Field

0 or PKIX-CA -- TODO

1 or PKIX-EE -- TODO

2 or DANE-TA -- TODO

3 or DANE-EE -- Implemented

4 or REJECT -- Implemented


The Selector Field

0 or CERT --  Implemented

1 or SPKI -- TODO

The Matching Type Field

0 or Full --  Implemented

1 or SHA2-256 -- TODO

2 or SHA2-512 -- TODO

Certificate Access Field

0 or NO -- Implemented

1 or NAPTR -- TODO

2 or WF -- TODO
