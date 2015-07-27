/*
   Copyright (c) <2015> Verisign, Inc.

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


#ifndef _SMG_PGP_ASSOCIATION_H
#define _SMG_PGP_ASSOCIATION_H

#include <string>

#include "smg_association.h"
#ifdef _SMG_NO_PGP
class SmgPgpKey
{
  public: 
    SmgPgpKey(){};
    virtual ~SmgPgpKey(){};
};
#else
#include "smg_pgp_key.h"
#endif
#include "smg_defs.h"

class SmgPgpAssociation : public SmgAssociation
{
  // Member Variables
  private:
    SmgPgpKey m_oKey;

  // Methods
  public:
    SmgPgpAssociation();
    SmgPgpAssociation(const SmgPgpAssociation &p_oRHS);
    virtual ~SmgPgpAssociation();

    bool init(SmgPgpKey &p_oKey);
    bool initLocal(std::string &p_sID, const char *p_szHomeDir = NULL);


    virtual bool toWire(SmgBytesVector_t &p_oOutput);
    virtual bool fromWire(uint8_t *p_pBuffer, size_t p_uLen);

    virtual bool toText(std::string &p_sOutput);
    virtual bool fromText(std::string &p_sTxt);

    SmgPgpKey &getKey();
    void setKey(SmgPgpKey &p_oKey);

    virtual bool verify(SmgBytesVector_t &p_oBytes);
    virtual bool encrypt(SmgBytesVector_t &p_oBytes,
                         SmgBytesVector_t &p_oEncryptedBytes);
    virtual bool encrypt(SmgBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted);
    virtual bool encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted);
    virtual bool decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                         SmgBytesVector_t &p_oBytes);
    virtual bool decrypt(std::string &p_sEncrypted,
                         SmgBytesVector_t &p_oBytes);
    virtual bool sign(SmgBytesVector_t &p_oBytes,
                      SmgBytesVector_t &p_oSignature);
    virtual bool sign(SmgBytesVector_t &p_oBytes,
                      std::string &p_sSignature);

    virtual SmgAssociation &operator=(const SmgPgpAssociation &p_oRHS);

    virtual bool clear();
};

#endif
