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

#include <openssl/pem.h>
#include <openssl/err.h>

#include <iostream>
// #include <sstream>

#include "dane_email.h"
#include "dane_openssl.h"

//static const int32_t EXIT_OK        =   0;
//static const int32_t EXIT_ERROR     =   1;
//static const int32_t EXIT_NO_RESULT = 100;

using namespace std;


// Must be null terminiated string buffer
int encryptBuffer( string & encryptedString, const string smimeaCert, const char * buf ) {

    char out_buf[MAX_BUF_SZ];
    memset( out_buf, '\0', MAX_BUF_SZ );

    BIO *in = NULL, *out_bio = NULL, *tbio = NULL;
    BIO *mem_buf = BIO_new(BIO_s_mem());

    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;

    const char * cert_buf = smimeaCert.c_str();

    /*
     * On OpenSSL 0.9.9 only:
     * for streaming set PKCS7_STREAM
     */
    //int flags = PKCS7_STREAM;
    int flags = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    //tbio = BIO_new_file("signer.pem", "r");
    tbio = BIO_new_mem_buf( (void *)cert_buf, -1 );

    if (!tbio)
	goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
	goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
	goto err;

    /* sk_X509_pop_free will free up recipient STACK and its contents
     * so set rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    // Load buffer for encryption
    in  = BIO_new_mem_buf( (void *)buf, -1 );

    if (!in)
	goto err;

    /* encrypt content */
    p7 = PKCS7_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!p7)
	goto err;
    
    // /* Write out_bio S/MIME message */
    //if (!SMIME_write_PKCS7(out_bio, p7, in, flags))
    if (!SMIME_write_PKCS7(mem_buf, p7, in, flags))
     	goto err;
    
    BIO_read(mem_buf, &out_buf[0], MAX_BUF_SZ);
    
    encryptedString = string(out_buf);

    BIO_free(mem_buf);

    ret = 0;

 err:

    if (ret) {
	fprintf(stderr, "Error Encrypting Data\n");
	ERR_print_errors_fp(stderr);
    }

    if (p7)
	PKCS7_free(p7);
    if (rcert)
	X509_free(rcert);
    if (recips)
	sk_X509_pop_free(recips, X509_free);
    if (in)
	BIO_free(in);
    if (out_bio)
	BIO_free(out_bio);
    if (tbio)
	BIO_free(tbio);

    return ret;
}


int getSMIMEA( string & smimeCert, const string emailAddress ) {
    
    DaneEmail daneEmailAddr(emailAddress.c_str(), emailAddress.size());
    
    uint8_t  certBuf[5000];
    uint32_t certLen;

    //#############################################
    // DEBUG: display internal certificate
    //#############################################
#if DEBUG_LEVEL_HIGH==1
    daneEmailAddr.printCerts();
#endif

    // Get copy of internal certificate
    uint8_t usage, type, selector;
    certLen = daneEmailAddr.getEncrCert(&certBuf[0], 5000, usage, type, selector);
    if (usage == 4) { // reject certificate
    	smimeCert = "";
    	std::cout << "Certificate rejected since the Certificate Usage Field is REJECT[" 
    		  << emailAddress << "]" << std::endl;
    	return(EXIT_NO_RESULT);
    }
    if (certLen) {	
    	// std::stringstream ss;
    	// ss << "-----BEGIN CERTIFICATE-----" << endl;

    	// uint8_t *ptr = &certBuf[0];
    	// for (uint32_t loop=0; loop<(certLen-1); ++loop) {
    	//     ss << std::hex << uint8_t(*ptr);
    	//     ++ptr;
    	// }
        
    	// ss << "-----END CERTIFICATE-----" << std::endl;
    	smimeCert = std::string((char *)certBuf, certLen);
    } else {
    	smimeCert = "";
    	std::cout << "No key response for email address ["
    		  << emailAddress << "]" << std::endl;
    	return(EXIT_NO_RESULT);
    }

    return 0;
}

int encrypt( string & resultStr, const string email, char * buf ) {
    
    string smimeaCert      = "";
    string encryptedString = "";

    getSMIMEA( smimeaCert, email );

    if (smimeaCert.size() == 0 ) {
	return 0;
    }

    if ( !encryptBuffer( encryptedString, smimeaCert, buf )) {
	// cout << "[" << encryptedString << "]" << endl;
	resultStr = encryptedString;
    }

    return 1;
}

extern "C" {
    const char* ds_encrypt(const char * email, const char * buf ) {

	static string encryptedString = "";
	encrypt(encryptedString, string(email), (char *)buf);

#if DEBUG_LEVEL_HIGH==1
    printf("encrypted text : %s\n", encryptedString.c_str());
#endif

	return encryptedString.c_str();
    }
}
