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


#ifndef _SMG_SMIME_ASSOCIATION_H
#define _SMG_SMIME_ASSOCIATION_H

#include <string>

#include "smg_smime_cert.h"
#include "smg_defs.h"

class SmgSmimeAssociation
{
  // Member Variables
  private:
    bool m_bInit;
    SmgUsage_e m_eUsage;
    SmgSelector_e m_eSelector;
    SmgMatching_e m_eMatching;
    SmgBytesVector_t m_oHash;
    SmgSmimeCert m_oCert;

  // Methods
  public:
    SmgSmimeAssociation();
    SmgSmimeAssociation(const SmgSmimeAssociation &p_oRHS);
    virtual ~SmgSmimeAssociation();

    bool init(SmgUsage_e p_eUsage,
              SmgSelector_e p_eSelector,
              SmgMatching_e p_eMatching,
              uint8_t *p_pCertAssocData,
              size_t p_uDataLen,
              SmgX509Encoding_e p_eEncoding = SMG_X509_DER);
    bool initFromFile(SmgUsage_e p_eUsage,
                      SmgSelector_e p_eSelector,
                      SmgMatching_e p_eMatching,
                      std::string &p_sFile);


    bool isInitialized();
    bool isFullCert();
    bool isFingerprintCert();
    bool isTA();
    bool isPKIX();
    bool isEE();

    SmgUsage_e getUsage();
    SmgSelector_e getSelector();
    SmgMatching_e getMatching();
    bool getHash(SmgBytesVector_t &p_oOutput);
    bool getHash(std::string &p_sOutput);

    bool toWire(SmgBytesVector_t &p_oOutput);
    bool fromWire(uint8_t *p_pBuffer, size_t p_uLen);

    bool toText(std::string &p_sOutput);
    bool fromText(std::string &p_sTxt);

    SmgSmimeCert &getCert();
    void setCert(SmgSmimeCert &p_oCert);

    virtual SmgSmimeAssociation &operator=(const SmgSmimeAssociation &p_oRHS);

    bool clear();
};

#endif
