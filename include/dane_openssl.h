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

#ifndef __DANE_OPENSSL_H__
#define __DANE_OPENSSL_H__

#include <string>
#include <iostream>


extern "C" {
// const char* js_tst(const char** outParam);
const char* hash_sha224  (const char * key);
const char* hash_sha256  (const char * key);
const char* hash_sha512  (const char * key);
const char* ds_encrypt   (const char * email, const char * buf );
const char* ds_decrypt   (const char * email, const char * buf );
const char* ds_sign      (const char * pem,   const char * buf );
//verify returns 1 == OK, 0 == ERR per CMS_verify
int ds_verify            (const char * emailBuffer, const char * emailAddress);
}

int encrypt     ( std::string & resultStr, const std::string email, char * buf );
int decrypt     ( std::string & resultStr, const std::string key,   char * buf );
int sign        ( std::string & resultStr, const std::string pem,   const char * buf );
int verify      ( const std::string emailBuffer, const std::string emailAddress  );
int hash_sha224 ( std::string & resultStr, const std::string textStr );
int hash_sha256 ( std::string & resultStr, const std::string textStr );
int hash_sha512 ( std::string & resultStr, const std::string textStr );

#endif
