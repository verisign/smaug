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


#include <stdio.h>
#include <inttypes.h>

#include <sstream>
#include <iomanip>

#include <errno.h>
#include <cstring>
#include <arpa/inet.h>

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
  if (isInitialized())
  {
    clear();
  }

  m_oKey = p_oKey;
  SmgAssociation::init();

  return isInitialized();
}

bool SmgPgpAssociation::initLocal(std::string &p_sID, const char *p_szHomeDir /*= NULL*/)
{
  if (isInitialized())
  {
    clear();
  }

  if (m_oKey.initLocal(p_sID, p_szHomeDir))
  {
    smg_log("Key is initialized.\n");
    SmgAssociation::init();
  }
  else
  {
    smg_log("Key is NOT initialized.\n");
  }

  return isInitialized();
}

bool SmgPgpAssociation::toWire(SmgBytesVector_t &p_oOutput)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Association is not initialized.\n");
  }
  else
  {
    p_oOutput.clear();

    uint8_t *pBytes = m_oKey.getBytes();
    size_t uLen = m_oKey.getBytesLen();
    p_oOutput.assign(pBytes, pBytes + uLen);
    bRet = SmgAssociation::init();
  }

  return bRet;
}

bool SmgPgpAssociation::fromWire(uint8_t *p_pBuffer, size_t p_uLen)
{
  bool bRet = false;

  if (NULL == p_pBuffer)
  {
    smg_log("NULL buffer specified.\n");
  }
  else if (0 == p_uLen)
  {
    smg_log("0 length buffer specified.\n");
  }
  else if (p_uLen > SMG_OPENPGPKEY_MAX_LEN)
  {
    smg_log("Buffer is greater than %lu > %u.\n", p_uLen, SMG_OPENPGPKEY_MAX_LEN);
  }
  else
  {
    bRet = m_oKey.init(p_pBuffer, p_uLen);
    if (bRet)
    {
      SmgAssociation::init();
    }
  }

  return bRet;
}

bool SmgPgpAssociation::toText(std::string &p_sOutput)
{
  bool bRet = false;

  SmgBytesVector_t oBytes;
  bRet = toWire(oBytes);
  if (bRet)
  {
    ostringstream oSS;
    size_t uLen = oBytes.size();
    oSS << "\\# " << uLen << " (";
    char szOct[4] = {0, 0, 0, 0};
    for (size_t u = 0; u < uLen; u++)
    {
      memset(szOct, 0, 4);
      sprintf(szOct, " %02x", oBytes[u]);
      oSS << szOct;
    }
    oSS << " )";

    p_sOutput = oSS.str();
  }

  return bRet;
}

bool SmgPgpAssociation::fromText(std::string &p_sTxt)
{
  bool bRet = false;

  size_t uLen = p_sTxt.size();

  if (uLen < SMG_SMIMEA_MIN_TXT_LEN)
  {
    smg_log("SMIMEA length %lu is too short (< %d)\n", uLen, SMG_SMIMEA_MIN_TXT_LEN);
  }
  else
  {
    stringstream oSS(p_sTxt);
    vector< string > oTokens;
    string sTok;
    while (std::getline(oSS, sTok, ' '))
    {
      if (!sTok.empty() 
          && sTok != "("
          && sTok != ")")
      {
        oTokens.push_back(sTok);
      }
    }

    sTok = oTokens.front();
    if (sTok != "\\#")
    {
      smg_log("First token is '%s', not '\\#'\n", sTok.c_str());
    }
    else
    {
      int iLen = 0;
      vector< string >::iterator tIter = oTokens.erase(oTokens.begin());
      if (oTokens.end() == tIter)
      {
        smg_log("Not enough tokens in input string '%s'\n", p_sTxt.c_str());
      }
      else if (0 == (iLen = (int) strtol((*tIter).c_str(), NULL, 10))
               && 0 != errno)
      {
        smg_log("Unable to convert length '%s' into int: %s\n", (*tIter).c_str(), strerror(errno));
      }
      else
      {
        stringstream oSS2;
        for (tIter = oTokens.erase(tIter);
             oTokens.end() != tIter;
             tIter++)
        {
          oSS2 << *tIter;
        }
        string sBytes = oSS2.str();

        if (iLen != sBytes.size()/2)
        {
          smg_log("The length field (%d) does not match the number of hex-encoded octets %d in '%s'\n",
                  iLen,
                  (int) sBytes.size()/2,
                  sBytes.c_str());
        }
        else
        {
          SmgBytesVector_t oBytes;
          const char *szBytes = sBytes.c_str();
          char szOctet[3] = {0, 0, 0};
          for (int i = 0; i < iLen*2; i++)
          {
            szOctet[0] = szBytes[i++];
            szOctet[1] = szBytes[i];
            uint8_t c = (uint8_t) strtol(szOctet, NULL, 16);
            oBytes.push_back(c);
          }

          bRet = fromWire(oBytes.data(), oBytes.size());
        }
      }
    }
  }

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

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.verify(p_oBytes);

  }

  return bRet;
}

bool SmgPgpAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         SmgBytesVector_t &p_oEncryptedBytes)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.encrypt(p_oBytes, p_oEncryptedBytes);

  }

  return bRet;
}

bool SmgPgpAssociation::encrypt(SmgBytesVector_t &p_oBytes,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.encrypt(p_oBytes, p_sEncrypted);

  }

  return bRet;
}

bool SmgPgpAssociation::encrypt(std::string &p_oClear,
                         std::string &p_sEncrypted)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.encrypt(p_oClear, p_sEncrypted);

  }

  return bRet;
}

bool SmgPgpAssociation::decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                         SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.decrypt(p_oEncryptedBytes, p_oBytes);

  }

  return bRet;
}

bool SmgPgpAssociation::decrypt(std::string &p_sEncrypted,
                         SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.decrypt(p_sEncrypted, p_oBytes);

  }

  return bRet;
}

bool SmgPgpAssociation::sign(SmgBytesVector_t &p_oBytes,
                      SmgBytesVector_t &p_oSignature)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.sign(p_oBytes, p_oSignature);

  }

  return bRet;
}

bool SmgPgpAssociation::sign(SmgBytesVector_t &p_oBytes,
                      std::string &p_sSignature)
{
  bool bRet = false;

  if (!isInitialized())
  {
    smg_log("Unable to sign until association is initialized.\n");
  }
  else
  {
    bRet = m_oKey.sign(p_oBytes, p_sSignature);

  }

  return bRet;
}

SmgAssociation &SmgPgpAssociation::operator=(const SmgPgpAssociation &p_oRHS)
{
  SmgAssociation::operator=(p_oRHS);
  m_oKey = p_oRHS.m_oKey;

  return *this;
}

bool SmgPgpAssociation::clear()
{
  m_oKey.clear();

  return true;
}

