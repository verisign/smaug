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
#include <string.h>

#include <sstream>
#include <iomanip>

#include "smg_id.h"
#include "smg_smime_association.h"

using namespace std;

SmgID::SmgID()
{

}

SmgID::SmgID(const SmgID &p_oRHS)
{
  *this = p_oRHS;
}

SmgID::~SmgID()
{
  clear();
}

bool SmgID::init(std::string &p_sEmailAddr)
{
  bool bRet = false;

  if (!clear())
  {
    fprintf(stderr, "Unable to clear ID.\n");
  }
  else
  {
    m_sEmailAddr = p_sEmailAddr;
    size_t uPos = m_sEmailAddr.find('@');
    if (string::npos == uPos)
    {
      fprintf(stderr, "Unable to find '@' in email address '%s'\n", m_sEmailAddr.c_str());
    }
    else
    {
      m_sUser = m_sEmailAddr.substr(0, uPos);
      m_sDomain = m_sEmailAddr.substr(uPos + 1);

      unsigned char pHash[SHA224_DIGEST_LENGTH];
      unsigned char szHash[SHA224_DIGEST_LENGTH + 1];
      memset(pHash, 0, SHA224_DIGEST_LENGTH);
      memset(szHash, 0, SHA224_DIGEST_LENGTH + 1);

      SHA256_CTX oContext;
      if (!SHA224_Init(&oContext))
      {
        fprintf(stderr, "Unable to init SHA224 context.\n");
      }
      else if (!SHA224_Update(&oContext, m_sUser.c_str(), m_sUser.size()))
      {
        fprintf(stderr, "Unable to update hash from user '%s'\n", m_sUser.c_str());
      }
      else if (!SHA224_Final(pHash, &oContext))
      {
        fprintf(stderr, "Unable to finalize hash.\n");
      }
      else
      {
        ostringstream oSS;
        char szOct[3] = {0, 0, 0};
        for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        {
          memset(szOct, 0, 3);
          sprintf(szOct, "%02x", pHash[i]);
          oSS << szOct;
          // oSS << hex << setfill('0') << setw(2) << pHash[i];
        }

        m_sUserHash = oSS.str();

	m_sSmimeName = m_sUserHash + "._smimecert." + m_sDomain;
        if (m_sSmimeName.compare(m_sSmimeName.size() - 1, 1, "."))
        {
          m_sSmimeName += ".";
        }

        bRet = true;
      }
    }
  }

  return bRet;
}

std::string &SmgID::getEmail()
{
  return m_sEmailAddr;
}

std::string &SmgID::getDomain()
{
  return m_sDomain;
}

std::string &SmgID::getSmimeName()
{
  return m_sSmimeName;
}

std::string &SmgID::getInbox()
{
  return m_sUser;
}

bool SmgID::addAssociation(SmgSmimeAssociation &p_oAssoc)
{
  bool bRet = false;

  if (!p_oAssoc.isInitialized())
  {
    smg_log("Cannot add uninitialized association.\n");
  }
  else
  {
    SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation(p_oAssoc);
    m_oAssocs.push_back(pAssoc);
    bRet = true;
  }

  return bRet;
}

SmgSmimeAssocKIter_t SmgID::beginSmimeAssociations() const
{
  return m_oAssocs.begin();
}

SmgSmimeAssocKIter_t SmgID::endSmimeAssociations() const
{
  return m_oAssocs.end();
}

size_t SmgID::numSmimeAssociations() const
{
  return m_oAssocs.size();
}

SmgID &SmgID::operator=(const SmgID &p_oRHS)
{
    smg_log("Copying ID %lu assocs\n", 
	    p_oRHS.numAssociations());
    m_sEmailAddr = p_oRHS.m_sEmailAddr;
    m_sUser      = p_oRHS.m_sUser;
    m_sUserHash  = p_oRHS.m_sUserHash;
    m_sDomain    = p_oRHS.m_sDomain;
    m_sSmimeName = p_oRHS.m_sSmimeName;

  SmgSmimeAssocKIter_t tIter;
  for (tIter = p_oRHS.beginSmimeAssociations();
       p_oRHS.endSmimeAssociations() != tIter;
       tIter++)
  {
    smg_log("Pushing assoc\n");
    SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation();
    *(pAssoc) = *(*tIter);
    m_oAssocs.push_back(pAssoc);
  }

  return *this;
}

bool SmgID::clear()
{
  SmgSmimeAssocKIter_t tIter;
  for (tIter = beginSmimeAssociations();
       endSmimeAssociations() != tIter;
       tIter++)
  {
    delete *tIter;
  }
  m_oAssocs.empty();

  return true;
}
