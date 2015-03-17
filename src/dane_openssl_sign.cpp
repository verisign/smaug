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

/*
  https://www.openssl.org/docs/crypto/crypto.html
  https://www.openssl.org/docs/crypto/PKCS7_decrypt.html
  https://www.openssl.org/docs/crypto/RSA_sign.html
*/


/* Simple S/MIME signing example */
/* code adapted from OpenSSL example code */
// https://raw.githubusercontent.com/openssl/openssl/master/demos/cms/cms_sign2.c
// http://wiki.openssl.org/index.php/Manual:SMIME_write_CMS(3)


#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#include <string>
#include <iostream>
#include <sstream>

#include <cstring>

#include "dane_enc.h"
#include "dane_email.h"
#include "dane_openssl.h"


int sign( std::string & resultStr, const std::string pem, const char * buf ) {
    std::cout << "DANE_EMIAIL::signing" << std::endl;

    char    out_buf[MAX_BUF_SZ];
    memset( out_buf, '\0', MAX_BUF_SZ );
    
    BIO *in              = NULL, 
        *tbio            = NULL;
    X509 *scert          = NULL;  //, *scert2 = NULL;
    EVP_PKEY *skey       = NULL;  // , *skey2 = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    BIO *mem_buf = BIO_new(BIO_s_mem());


    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Prep and Load Certificate
    tbio = BIO_new_mem_buf((void *)pem.data(), pem.size());
    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!scert) {
    std::cout << "Error Reading X509 Certificate" << std::endl;
        goto err;
    }
    std::cout << "Read CERT [OK]" << std::endl;

    BIO_reset(tbio);

    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!skey) {
        std::cout << "Error Reading Private Key" << std::endl;
        goto err;
    }

    std::cout << "Read PKEY [OK]" << std::endl;

    //BIO_free(tbio);

    // tbio = BIO_new_file("signer2.pem", "r");
    // if (!tbio)
    //     goto err;
    // scert2 = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    // BIO_reset(tbio);

    // skey2 = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    // if (!scert2 || !skey2)
    //     goto err;

    /* Sign S/MIME message */
    in = BIO_new_mem_buf((void *)buf, strlen(buf));
    if (!in)
        goto err;

    cms = CMS_sign(NULL, NULL, NULL, in, CMS_STREAM|CMS_DETACHED);

    if (!cms)
        goto err;

    /* Add each signer in turn */

    if (!CMS_add1_signer(cms, scert, skey, NULL, 0))
        goto err;

    // if (!CMS_add1_signer(cms, scert2, skey2, NULL, 0))
    //     goto err;


    /* NB: content included and finalized by SMIME_write_CMS */

    if (!SMIME_write_CMS(mem_buf, cms, in, CMS_STREAM|CMS_DETACHED))
        goto err;

    BIO_read(mem_buf, &out_buf[0], MAX_BUF_SZ);
    resultStr = std::string(out_buf);

#if DEBUG_LEVEL_HIGH==1
    std::cout << "resultStr [" << resultStr << "]" << std::endl;
#endif

    ret = 0;

 err:

    if (ret){
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);

    if (scert)
        X509_free(scert);
    if (skey)
        EVP_PKEY_free(skey);

    // if (scert2)
    //     X509_free(scert2);
    // if (skey)
    //     EVP_PKEY_free(skey2);

    if (in)
        BIO_free(in);
    if (mem_buf)
        BIO_free(mem_buf);
    if (tbio)
        BIO_free(tbio);

    return ret;

}

//verify returns 1 == OK, 0 == ERR
int verify      ( const std::string mailBuf, const std::string emailAddress ) {
    int ret = 0;

    std::cout << "Email [" << emailAddress << "]" << std::endl;

    // get the _sign emailAddr 
    DaneEmail daneEmailAddr(emailAddress.c_str(), emailAddress.size());
    
    uint8_t  certBuf[5000];
    uint32_t certLen;
    std::string smimeCert = "";
    //#############################################
    // DEBUG: display internal certificate
    //#############################################
#if DEBUG_LEVEL_HIGH==1
    daneEmailAddr.printCerts();
#endif

    // Get copy of internal certificate
    uint8_t usage, type, selector;
    certLen = daneEmailAddr.getSignCert(&certBuf[0], 5000, usage, type, selector);
    if (usage == 4) { // reject certificate
        smimeCert = "";
        std::cout << "Certificate rejected since the Certificate Usage Field is REJECT["
                  << emailAddress << "]" << std::endl;
        return(EXIT_NO_RESULT);
    }

    if (certLen) {  
        // std::stringstream ss;
        // ss << "-----BEGIN CERTIFICATE-----" << std::endl;

        // uint8_t *ptr = &certBuf[0];
        // for (uint32_t loop=0; loop<(certLen-1); ++loop) {
        //     ss << std::hex << uint8_t(*ptr);
        //     ++ptr;
        // }
        
        // ss << "-----END CERTIFICATE-----" << std::endl;
        smimeCert = std::string((char *)certBuf, certLen);
    } else {
        smimeCert = "";
        std::cout << "dane_openssl_sign: No key response for email address ["
            << emailAddress << "]" << std::endl;
    return(0);
    }

    std::cout << smimeCert << std::endl;

    std::string oldEmail = mailBuf;
    int start_pos = oldEmail.find("-signature\";", 0);
    start_pos += strlen("-signature\";");

    int end_pos = oldEmail.find("micalg", 0);
    
    std::string email = oldEmail.substr(0, start_pos) + " " + oldEmail.substr(end_pos, oldEmail.size() - end_pos);

    // std::cout << "email buffer :" << std::endl << email << std::endl;

    BIO *in = NULL, *out = NULL;
    BIO  *tbio = NULL, *cont = NULL;

    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();

    /* Read in CA certificate */
    // tbio = BIO_new_file("cacert.pem", "r");
    tbio = BIO_new_mem_buf((void *)smimeCert.data(), smimeCert.size());
    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
    	goto err;

    if (!X509_STORE_add_cert(st, cacert))
    	goto err;

    /* Open message being verified */
    in = BIO_new_mem_buf((void *)email.data(), email.size());
    if (!in)
    	goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
    	goto err;

    // Make the cert verification tight
    // if (!CMS_verify(cms, NULL, st, cont, NULL, CMS_NO_SIGNER_CERT_VERIFY)) {
    if (!CMS_verify(cms, NULL, st, cont, NULL, 0)) {
#if DEBUG_LEVEL_HIGH==1
	    std::cout << "Verification Failure" << std::endl; 
#endif
	    goto err;
	}

#if DEBUG_LEVEL_HIGH==1
    std::cout << "Verification Successful" << std::endl; 
#endif
    ret = 1;

 err:
    if (!ret){
	    fprintf(stderr, "Error Verifying Data\n");
	    ERR_print_errors_fp(stderr);
    }

    if (cms)
	CMS_ContentInfo_free(cms);

    if (cacert)
	X509_free(cacert);

    if (in)
	BIO_free(in);
    if (out)
	BIO_free(out);
    if (tbio)
	BIO_free(tbio);

    return ret;
}

extern "C" {
    const char* ds_sign      (const char * pem, const char * buf ) {

	// printf("key :%s\n", key);
	// printf("buffer :%s\n", buf);
    
	std::cout << "PEM File: " << std::string(pem) << std::endl;
	std::cout << "Email Body [" << std::string(buf) << "]" << std::endl;

	static std::string emailBody = "";
	sign( emailBody, std::string(pem), (char *)buf);

#if DEBUG_LEVEL_HIGH==1
	printf("text : %s\n", emailBody.c_str());
#endif

	// return ("simple return code");
	return emailBody.c_str();
    }

    //verify returns 1 == OK, 0 == ERR
    int ds_verify      (const char * emailBuffer, const char * emailAddress) {
	   return verify(std::string(emailBuffer), std::string(emailAddress));
    }
}

