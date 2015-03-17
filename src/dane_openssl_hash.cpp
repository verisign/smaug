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

// From example
// http://www.askyb.com/cpp/openssl-sha224-hashing-example-in-cpp/

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "dane_enc.h"
#include "dane_openssl.h"


extern "C" {
    const char* hash_sha224(const char* key) {
	unsigned char digest[SHA224_DIGEST_LENGTH];
 
	SHA256_CTX ctx;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, key, strlen(key));
	SHA224_Final(digest, &ctx);
 
	std::string resultStr = "";
    
	hash_sha224(resultStr, std::string(key));
	return resultStr.c_str();
    }

    const char* hash_sha256(const char* key) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
 
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, strlen(key));
	SHA256_Final(digest, &ctx);
 
	std::string resultStr = "";
    
	hash_sha256(resultStr, std::string(key));
	return resultStr.c_str();
    }
    
    const char* hash_sha512(const char* key) {
	unsigned char digest[SHA512_DIGEST_LENGTH];
 
	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, strlen(key));
	SHA512_Final(digest, &ctx);
 
	std::string resultStr = "";
    
	hash_sha512(resultStr, std::string(key));
	return resultStr.c_str();
    }
}

int hash_sha224( std::string & resultStr, const std::string textStr ) {

    unsigned char digest[SHA224_DIGEST_LENGTH];
 
    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    SHA224_Update(&ctx, textStr.c_str(), textStr.size());
    SHA224_Final(digest, &ctx);
 
    char mdString[SHA224_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
 
    resultStr = std::string(mdString);
 
    return 0;
}

int hash_sha256( std::string & resultStr, const std::string textStr ) {

    unsigned char digest[SHA256_DIGEST_LENGTH];
 
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, textStr.c_str(), textStr.size());
    SHA256_Final(digest, &ctx);
 
    char mdString[SHA256_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
 
    printf("SHA256 digest: %s\n", mdString);

    resultStr = std::string(mdString);
    return 0;
}

int hash_sha512( std::string & resultStr, const std::string textStr ) {

    unsigned char digest[SHA512_DIGEST_LENGTH];
 
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, textStr.c_str(), textStr.size());
    SHA512_Final(digest, &ctx);
 
    char mdString[SHA512_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
 
    printf("SHA512 digest: %s\n", mdString);
    resultStr = std::string(mdString);
    return 0;
}
