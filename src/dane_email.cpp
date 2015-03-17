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
#include <string>
#include <cstring>
#include <cstdlib>
// #include <stdlib.h>
// #include <string.h>
#include <inttypes.h>


#include "dane_email.h"
#include "dane_openssl.h"

DaneEmail::DaneEmail(const std::string n_emailAddr) {
    DaneEmail(n_emailAddr.c_str(), n_emailAddr.size());
}

DaneEmail::DaneEmail(const char *n_emailAddr, uint32_t length) {

    // vrfy length of email and QUERY_LABEL is OK
    if ( (length+strlen(DANE_SMTP_QUERY_LABEL)+1) > MAX_DOMAIN_LENGTH ) {
	// we have a problem.  the resulting query will be too large
	exit(-1);
    }

    memset(&emailAddr[0],  '\0', MAX_EMAIL_ADDRESS_LEN);
    emailAddrLen  = 0;
    addrHash      = "";
    memset(&domainAddr[0], '\0', MAX_DOMAIN_LENGTH);
    
    if (length > MAX_EMAIL_ADDRESS_LEN) {
	exit(-1);
    }

    memcpy(&emailAddr[0], n_emailAddr, length);
    emailAddrLen = length;

    valid = spc_email_isvalid(n_emailAddr);

    setDomain();
    encodeAddr();

    std::string addrEncr = addrHash + "._encr." + std::string(DANE_SMTP_QUERY_LABEL) + "." + addrDomain;
    std::string addrSign = addrHash + "._sign." + std::string(DANE_SMTP_QUERY_LABEL) + "." + addrDomain;
    
    certEncr.setCertificateInfo(addrEncr);
    certSign.setCertificateInfo(addrSign);

    return;
}

DaneEmail::~DaneEmail() { 
    return; 
}

bool DaneEmail::isValidEmail() {

    return valid;
}

void DaneEmail::setDomain() {
    char         *src = &emailAddr[0];
    uint16_t      cnt  = 0;

#if DEBUG_LEVEL_HIGH==1
    std::cout << "setDomain: Email Addr [" << emailAddr << "]" << std::endl;
#endif

    while (*src != '@' && (cnt < emailAddrLen)) {
    	++src;
    	++cnt;
    }
    // skip the '@' sign 
    ++src;

    addrDomain = std::string(src);
    
#if DEBUG_LEVEL_MEDIUM==1
    std::cout << "setDomain: Base Domain [" << addrDomain << "]" << std::endl;
#endif
    
    return;
}

void DaneEmail::encodeAddr() {
    char     *src = &emailAddr[0];
    int       len = 0;
    
    while ( *src ) {
	if ( *src=='@' ) {
	    len = src - &emailAddr[0];
	    break;
	}
	++src;
    }
    
    hash_sha224( addrHash, std::string(&emailAddr[0], len));
#if 0    
#if DEBUG_LEVEL_HIGH==1
    std::cout << "SHA224 Hash (pre-trim) [" << addrHash << "]" << std::endl;    
#endif
    
#if DEBUG_LEVEL_HIGH==1
    std::cout << "SHA224 Hash [" << addrHash << "]" << std::endl;    
#endif
#endif
}

uint32_t  DaneEmail::getEncrCert(uint8_t * certBuf, uint32_t certSize,
                                 uint8_t& usage, uint8_t& type, uint8_t& selector) {
    return ( certEncr.getCert( certBuf, certSize, usage, type, selector ) );
}

uint32_t  DaneEmail::getSignCert(uint8_t * certBuf, uint32_t certSize,
                                 uint8_t& usage, uint8_t& type, uint8_t& selector) {
    return ( certSign.getCert( certBuf, certSize, usage, type, selector ) );
}

void DaneEmail::printCerts() {
    std::cout << "DaneEmail::printCerts [Encr Certificate]" << std::endl; 
    certEncr.printCert();
    std::cout << "DaneEmail::printCerts [Sign Certificate]" << std::endl; 
    certSign.printCert();
    return;
}

