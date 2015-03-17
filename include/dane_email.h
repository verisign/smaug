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

#ifndef __DANE_EMAIL_H__
#define __DANE_EMAIL_H__

#include <stdint.h>
#include <string>
#include <cstring>
#include <cstdlib>

#include "dane_enc.h"
#include "dane_cert.h"

static const int32_t EXIT_OK        =   0;
static const int32_t EXIT_ERROR     =   1;
static const int32_t EXIT_NO_RESULT = 100;

inline int spc_email_isvalid(const char *address);

class DaneEmail {
 public:
    DaneEmail(const std::string n_emailAddr);
    DaneEmail(const char *n_emailAddr, uint32_t length);
    ~DaneEmail();

    bool      isValidEmail();
    // uint16_t  getCertType();
    // int       getPublicCert( unsigned char *n_cert, uint32_t n_certLen ); 
    
 private:
    char         emailAddr[MAX_EMAIL_ADDRESS_LEN];
    uint32_t     emailAddrLen;

    std::string  addrDomain;
    std::string  addrHash;

    char         domainAddr[MAX_DOMAIN_LENGTH];

    bool         valid;
    Certificate  certEncr;
    Certificate  certSign;

    void         setDomain();
    void         encodeAddr();

 public:
    uint32_t     getEncrCert(uint8_t * cert, uint32_t certSize,
                             uint8_t& usage, uint8_t& type, uint8_t& selector);
    uint32_t     getSignCert(uint8_t * cert, uint32_t certSize,
                             uint8_t& usage, uint8_t& type, uint8_t& selector);
    //*******************************************
    void printCerts();
    std::string getHash() { return addrHash; };
};

// borrowed from 
// http://www.oreillynet.com/network/excerpt/spcookbook_chap03/index3.html
// RFC 822 Check
int spc_email_isvalid(const char *address) {
    int        count = 0;
    const char *c, *domain;
    static std::string _rfc822_specials_ = "()<>@,;:\\\"[]";;
    static const char *rfc822_specials   = _rfc822_specials_.c_str();

    /* first we validate the name portion (name@domain) */
    for (c = address;  *c;  c++) {
	if (*c == '\"' && (c == address || *(c - 1) == '.' || *(c - 1) == 
			   '\"')) {
	    while (*++c) {
		if (*c == '\"') break;
		if (*c == '\\' && (*++c == ' ')) continue;
		if (*c <= ' ' || *c >= 127) return 0;
	    }
	    if (!*c++) return 0;
	    if (*c == '@') break;
	    if (*c != '.') return 0;
	    continue;
	}
	if (*c == '@') break;
	if (*c <= ' ' || *c >= 127) return 0;
	if (strchr(rfc822_specials, *c)) return 0;
    }
    if (c == address || *(c - 1) == '.') return 0;

    /* next we validate the domain portion (name@domain) */
    if (!*(domain = ++c)) return 0;
    do {
	if (*c == '.') {
	    if (c == domain || *(c - 1) == '.') return 0;
	    count++;
	}
	if (*c <= ' ' || *c >= 127) return 0;
	if (strchr(rfc822_specials, *c)) return 0;
    } while (*++c);
    // cout << "here count [" << count << "]" <<  endl;
    return (count >= 1);
}
#endif
