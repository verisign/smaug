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


#include "smg_pgp_association.h"
#include "smg_defs.h"

using namespace std;

SmgPgpAssociation::SmgPgpAssociation()
  : SmgAssociation()
{

}

SmgPgpAssociation::SmgPgpAssociation(const SmgPgpAssociation &p_oRHS)
  : SmgAssociation()
{
  (*this) = p_oRHS;
}

SmgPgpAssociation::~SmgPgpAssociation()
{
  clear();
}

bool SmgPgpAssociation::init(SmgPgpKey &p_oKey)
{
  return isInitialized();
}

bool SmgPgpAssociation::initLocal(std::string &p_sID, const char *p_szHomeDir /*= NULL*/)
{
  return isInitialized();
}

bool SmgPgpAssociation::toWire(SmgBytesVector_t &p_oOutput)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  return bRet;
}

SmgPgpKey &SmgPgpAssociation::getKey()
{
  return m_oKey;
}

void SmgPgpAssociation::setKey(SmgPgpKey &p_oKey)
{
  m_oKey = p_oKey;
}

bool SmgPgpAssociation::verify(SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         SmgBytesVector_t &p_oEncryptedBytes)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                         SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::decrypt(std::string &p_sEncrypted,
                         SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::sign(SmgBytesVector_t &p_oBytes,
                      SmgBytesVector_t &p_oSignature)
{
  bool bRet = false;

  return bRet;
}

bool SmgPgpAssociation::sign(SmgBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  bool bRet = false;

  return bRet;
}

SmgAssociation &SmgPgpAssociation::operator=(const SmgPgpAssociation &p_oRHS)
{
  SmgAssociation::operator=(p_oRHS);

  return *this;
}

bool SmgPgpAssociation::clear()
{

  return false;
}

