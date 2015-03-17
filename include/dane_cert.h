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

#ifndef __DANE_CERT_H__
#define __DANE_CERT_H__

#include <stdint.h>
#include <string>
#include <cstring>
#include <cstdlib>

#include "dane_enc.h"

class Certificate {
 public:
    std::string record;
    bool        valid;
    uint32_t    getdns_response_status;
    uint16_t    certType;
    uint32_t    certLen;
    uint8_t     cert[MAX_CERTIFICATE_LEN];

    uint8_t     cert_usage;
    uint8_t     cert_selector;
    uint8_t     cert_matching_type;
    uint8_t     cert_access;

    Certificate();
    ~Certificate();
    uint16_t  getCertType();
    uint32_t  getResponseStatus();
    void      printCert();
    uint32_t  getCert(uint8_t * certBuf, uint32_t certSize,
                      uint8_t& usage, uint8_t& type, uint8_t& selector);
    void      setCertificateInfo(const std::string record);

 private:
    int getDnsData();
};

#endif
