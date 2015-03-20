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


#ifndef _SMG_SMIME_CERT_H
#define _SMG_SMIME_CERT_H

#include <openssl/pem.h>

#include <string>

#include "smg_defs.h"

class SmgSmimeCert
{
  // Member Variables
  private:
    bool m_bInit;
    uint8_t *m_pCertBuf;
    uint8_t *m_pPrivKeyBuf;
    size_t m_uCertBufLen;
    size_t m_uPrivKeyBufLen;
    X509 *m_pCert;
    EVP_PKEY *m_pPubKey;
    EVP_PKEY *m_pPrivKey;
    // CMS_ContentInfo *m_pCMS;
    X509_STORE *m_pStore;

  // Methods
  public:
    SmgSmimeCert();
    virtual ~SmgSmimeCert();

    bool init(SmgBytesVector_t &p_oBytes, SmgX509Encoding_e p_eEncoding = SMG_X509_PEM);
    bool initFromFile(std::string &p_sFile);
    bool init(uint8_t *p_pBytes, size_t p_uBytesLen, SmgX509Encoding_e p_eEncoding = SMG_X509_PEM);
    /*
    bool init(std::string &p_sCertFile,
              std::string &p_sPrivKeyFile);
    */
    bool calcCertAssocData(SmgSelector_e p_eSelector,
                  SmgMatching_e p_eMatching,
                  SmgBytesVector_t &p_oHash);
    bool calcCertAssocData(SmgSelector_e p_eSelector,
                  SmgMatching_e p_eMatching,
                  std::string &p_sHash);
    bool clear();

    uint8_t *getPrivateKey();
    size_t getPrivateKeyLen();

    uint8_t *getBytes();
    size_t getBytesLen();

    bool verify(SmgBytesVector_t &p_oBytes);
    bool encrypt(SmgBytesVector_t &p_oBytes,
                 SmgBytesVector_t &p_oEncryptedBytes);
    bool encrypt(SmgBytesVector_t &p_oBytes,
                 std::string &p_sEncrypted);
    bool encrypt(std::string &p_oClear,
                 std::string &p_sEncrypted);
    bool decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                 SmgBytesVector_t &p_oBytes);
    bool decrypt(std::string &p_sEncrypted,
                 SmgBytesVector_t &p_oBytes);
    bool sign(SmgBytesVector_t &p_oBytes,
              SmgBytesVector_t &p_oSignature);
    bool sign(SmgBytesVector_t &p_oBytes,
              std::string &p_sSignature);

    virtual SmgSmimeCert &operator=(SmgSmimeCert const &p_oRHS);

};

#endif
