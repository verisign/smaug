/*
Copyright (c) <2014> Verisign, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <cstring>
#include <cstdlib>

#include "dane_email.h"

using namespace std;

void usage() {
    std::cout << "Usage: test_dane_email <email address>" << std::endl;
    exit(-1);
}

int main( int argc, const char* argv[] ) {
    if (argc != 2) {
	usage();
    }

    std::string name = string(argv[1]);
    std::cout << "test_dane_email:: email address [" << argv[1] << "]" << std::endl;

    DaneEmail daneEmailAddr(name.c_str(), name.size());
    
    uint8_t  certBuf[5000];
    uint32_t certLen;

    std::cout << "test_dane_email:: sha224 hash [" <<  daneEmailAddr.getHash() << std::endl;

    //#############################################
    // display internal certificate
    //#############################################
    daneEmailAddr.printCerts();

    // Get copy of internal certificate
    uint8_t usage, type, selector;
    certLen = daneEmailAddr.getEncrCert(&certBuf[0], 5000, usage, type, selector);
    
    // output copy of encryption certificate for validation/doublecheck
    if (certLen) {
	std::cout << "DANE_EMAIL_TEST: certificate/key length [" << std::dec
		  << certLen
		  << "]" << std::endl;
	uint8_t *ptr = &certBuf[0];
	std::cout << "DANE_EMAIL_TEST: The Cert value is [\n";
	for (uint32_t loop=0; loop<certLen; ++loop) {
	    std::cout << std::hex << uint8_t(*ptr);
	    ++ptr;
	}

        std::cout << "]" << std::endl;
    } else {
	std::cout << "No _encr key response for email address ["
		  << name << "]" << std::endl;
    }
    
    return 0;
}
