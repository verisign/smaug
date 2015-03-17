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

/* Simple S/MIME signing example */

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#include <string>
#include <iostream>
#include <cstring>

#include "dane_enc.h"
#include "dane_openssl.h"


int decrypt( std::string & resultStr, const std::string key,   char * buf ) {
    std::cout << "DANE_EMIAIL::decrypt" << std::endl;

    char out_buf[MAX_BUF_SZ];
    memset( out_buf, '\0', MAX_BUF_SZ );

    BIO *mem_buf = BIO_new(BIO_s_mem());

    BIO *in = NULL, *out = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    BIO *tbio = BIO_new_mem_buf((void*)key.data(), key.size());

    if (!tbio)
	goto err;

    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rkey)
	goto err;

    /* Open S/MIME message to decrypt */
    in = BIO_new_mem_buf(buf, strlen(buf));

    if (!in)
	goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
	goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, NULL, NULL, mem_buf, 0))
	goto err;

    BIO_read(mem_buf, &out_buf[0], MAX_BUF_SZ);
    
    resultStr = std::string(out_buf);

    BIO_free(mem_buf);

    ret = 0;

 err:

    if (ret)
	{
	    fprintf(stderr, "Error Decrypting Data\n");
	    ERR_print_errors_fp(stderr);
	}

    if (cms)
	CMS_ContentInfo_free(cms);
    if (rkey)
	EVP_PKEY_free(rkey);

    if (in)
	BIO_free(in);
    if (out)
	BIO_free(out);
    if (tbio)
	BIO_free(tbio);

    return ret;

}

extern "C" {
    const char* ds_decrypt(const char * key, const char * buf ) {

	// printf("key :%s\n", key);
	// printf("buffer :%s\n", buf);
    
	static std::string emailBody = "";
	decrypt(emailBody, std::string(key), (char *)buf);

#if DEBUG_LEVEL_HIGH==1
    printf("text : %s\n", emailBody.c_str());
#endif

    // return ("simple return code");
	return emailBody.c_str();
    }
}
