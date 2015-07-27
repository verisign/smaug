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


#include <stdio.h>
#include <inttypes.h>

#include "smg_smime_association.h"
#include "smg_defs.h"

using namespace std;

SmgSmimeAssociation::SmgSmimeAssociation()
  : m_eUsage(USG_PRE_INIT),
    m_eSelector(SEL_PRE_INIT),
    m_eMatching(MAT_PRE_INIT)
{

}

SmgSmimeAssociation::SmgSmimeAssociation(const SmgSmimeAssociation &p_oRHS)
  : m_eUsage(USG_PRE_INIT),
    m_eSelector(SEL_PRE_INIT),
    m_eMatching(MAT_PRE_INIT)
{
  (*this) = p_oRHS;
}

SmgSmimeAssociation::~SmgSmimeAssociation()
{
  clear();
}

bool SmgSmimeAssociation::init(SmgUsage_e p_eUsage,
              SmgSelector_e p_eSelector,
              SmgMatching_e p_eMatching,
              uint8_t *p_pCertAssocData,
              size_t p_uDataLen,
              SmgX509Encoding_e p_eEncoding /*= SMG_X509_DER*/)
{
  return isInitialized();
}

bool SmgSmimeAssociation::initFromFile(SmgUsage_e p_eUsage,
                                       SmgSelector_e p_eSelector,
                                       SmgMatching_e p_eMatching,
                                       std::string &p_sFile)
{
  return isInitialized();
}

bool SmgSmimeAssociation::isFullCert()
{
  return (SEL_FULL == m_eSelector && MAT_FULL == m_eMatching);
}

bool SmgSmimeAssociation::isFingerprintCert()
{
  return MAT_FULL != m_eMatching;
}

bool SmgSmimeAssociation::isTA()
{
  return USG_PKIX_TA == m_eUsage || USG_DANE_TA == m_eUsage;
}

bool SmgSmimeAssociation::isPKIX()
{
  return USG_PKIX_TA == m_eUsage || USG_PKIX_EE == m_eUsage;
}

bool SmgSmimeAssociation::isEE()
{
  return USG_PKIX_EE== m_eUsage || USG_DANE_EE == m_eUsage;
}

SmgUsage_e SmgSmimeAssociation::getUsage()
{
  return m_eUsage;
}

SmgSelector_e SmgSmimeAssociation::getSelector()
{
  return m_eSelector;
}

SmgMatching_e SmgSmimeAssociation::getMatching()
{
  return m_eMatching;
}

bool SmgSmimeAssociation::getHash(SmgBytesVector_t &p_oOutput)
{
  bool bRet = false;

  return true;;
}

bool SmgSmimeAssociation::getHash(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool SmgSmimeAssociation::toWire(SmgBytesVector_t &p_oOutput)
{
  bool bRet = false;

  return bRet;
}

bool SmgSmimeAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  return bRet;
}

bool SmgSmimeAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool SmgSmimeAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  return bRet;
}

SmgSmimeCert &SmgSmimeAssociation::getCert()
{
  return m_oCert;
}

void SmgSmimeAssociation::setCert(SmgSmimeCert &p_oCert)
{
  m_oCert = p_oCert;
}

bool SmgSmimeAssociation::verify(SmgBytesVector_t &p_oBytes)
{
  return false;
}

bool SmgSmimeAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         SmgBytesVector_t &p_oEncryptedBytes)
{
  return false;
}

bool SmgSmimeAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  return false;
}

bool SmgSmimeAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  return false;
}

bool SmgSmimeAssociation::decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                         SmgBytesVector_t &p_oBytes)
{
  return false;
}

bool SmgSmimeAssociation::decrypt(std::string &p_sEncrypted,
                         SmgBytesVector_t &p_oBytes)
{
  return false;
}

bool SmgSmimeAssociation::sign(SmgBytesVector_t &p_oBytes,
                      SmgBytesVector_t &p_oSignature)
{
  return false;
}

bool SmgSmimeAssociation::sign(SmgBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  return false;
}

SmgAssociation &SmgSmimeAssociation::operator=(const SmgSmimeAssociation &p_oRHS)
{
  SmgAssociation::operator=(p_oRHS);
  m_eUsage = p_oRHS.m_eUsage;
  m_eSelector = p_oRHS.m_eSelector;
  m_eMatching = p_oRHS.m_eMatching;
  m_oHash = p_oRHS.m_oHash;

  return *this;
}

bool SmgSmimeAssociation::clear()
{
  m_bInit = false;
  m_eUsage = USG_PRE_INIT;
  m_eSelector = SEL_PRE_INIT;
  m_eMatching = MAT_PRE_INIT;

  return true;
}

