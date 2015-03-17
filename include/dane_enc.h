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

#ifndef __DANE_ENCODE_H__
#define __DANE_ENCODE_H__

#include <stdint.h>
#include <string>

#define MAX_CERTIFICATE_LEN      5000
#define MAX_EMAIL_ADDRESS_LEN     256
#define MAX_DOMAIN_LENGTH         253

#define UNKNOWN_CERTIFICATE_TYPE 9999
#define BAD_CERTIFICATE_TYPE      999

static const std::string default_socket = "._dane_email";

static const std::string OPENSSL("/usr/bin/openssl");
static const int         MAX_BUF_SZ = 4096*4;

static const char ENCODING_PAD_CHAR = '=';
static const char DANE_SMTP_QUERY_LABEL[]  = {"_smimecert"};
static const char DANE_EMAIL_RR_TYPE_STR[] = {"type65514"};
static const uint16_t DANE_EMAIL_RR_TYPE   = 65514;


const std::string CMD_TEXT[] = {
    "unknown",
    "ENCRYPT",
    "DECRYPT",
    "HASH",
    "EMAIL",
    "KEY",
    "DATA"
};

enum CMD {
    UNKNOWN,
    ENCRYPT,
    DECRYPT,
    HASH,
    EMAIL,
    KEY,
    DATA
};

enum HASH_TYPE {
    sha1,
    sha256
};

#endif
