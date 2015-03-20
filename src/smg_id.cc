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

        m_sEncName = m_sUserHash + "._encr._smimecert." + m_sDomain;
        if (m_sEncName.compare(m_sEncName.size() - 1, 1, "."))
        {
          m_sEncName += ".";
        }
        m_sSignName = m_sUserHash + "._sign._smimecert." + m_sDomain;
        if (m_sSignName.compare(m_sEncName.size() - 1, 1, "."))
        {
          m_sSignName += ".";
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

std::string &SmgID::getEncName()
{
  return m_sEncName;
}

std::string &SmgID::getSignName()
{
  return m_sSignName;
}

std::string &SmgID::getInbox()
{
  return m_sUser;
}

bool SmgID::addAssociation(SmgSmimeAssociation &p_oAssoc)
{
  bool bRet = false;

  if (!p_oAssoc.isEncCert() && !p_oAssoc.isSignCert())
  {
    fprintf(stderr, "S/MIME cert is _neither_ for signing nor encryption?\n");
  }
  else
  {
    if (p_oAssoc.isEncCert())
    {
      SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation(p_oAssoc);
      m_oEncAssocs.push_back(pAssoc);
      bRet = true;
    }

    if (p_oAssoc.isSignCert())
    {
      SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation(p_oAssoc);
      m_oSignAssocs.push_back(pAssoc);
      bRet = true;
    }
  }

  return bRet;
}

SmgSmimeAssocKIter_t SmgID::beginEncAssociations() const
{
  return m_oEncAssocs.begin();
}

SmgSmimeAssocKIter_t SmgID::endEncAssociations() const
{
  return m_oEncAssocs.end();
}

size_t SmgID::numEncAssociations() const
{
  return m_oEncAssocs.size();
}

SmgSmimeAssocKIter_t SmgID::beginSignAssociations() const
{
  return m_oSignAssocs.begin();
}

SmgSmimeAssocKIter_t SmgID::endSignAssociations() const
{
  return m_oSignAssocs.end();
}

size_t SmgID::numSignAssociations() const
{
  return m_oSignAssocs.size();
}

SmgID &SmgID::operator=(const SmgID &p_oRHS)
{
  smg_log("Copying ID %lu signing assocs and %lu encryption assocs\n", 
      p_oRHS.numSignAssociations(),
      p_oRHS.numEncAssociations());
  m_sEmailAddr = p_oRHS.m_sEmailAddr;
  m_sUser = p_oRHS.m_sUser;
  m_sUserHash = p_oRHS.m_sUserHash;
  m_sDomain = p_oRHS.m_sDomain;
  m_sEncName = p_oRHS.m_sEncName;
  m_sSignName = p_oRHS.m_sSignName;

  SmgSmimeAssocKIter_t tIter;
  for (tIter = p_oRHS.beginEncAssociations();
       p_oRHS.endEncAssociations() != tIter;
       tIter++)
  {
    smg_log("Pushing signing assoc\n");
    SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation();
    *(pAssoc) = *(*tIter);
    m_oEncAssocs.push_back(pAssoc);
  }

  for (tIter = p_oRHS.beginSignAssociations();
       p_oRHS.endSignAssociations() != tIter;
       tIter++)
  {
    smg_log("Pushing encryption assoc\n");
    SmgSmimeAssociation *pAssoc = new SmgSmimeAssociation();
    (*pAssoc) = *(*tIter);
    m_oSignAssocs.push_back(pAssoc);
  }

  return *this;
}

bool SmgID::clear()
{
  SmgSmimeAssocKIter_t tIter;
  for (tIter = beginEncAssociations();
       endEncAssociations() != tIter;
       tIter++)
  {
    delete *tIter;
  }
  m_oEncAssocs.empty();

  for (tIter = beginSignAssociations();
       endSignAssociations() != tIter;
       tIter++)
  {
    delete *tIter;
  }
  m_oSignAssocs.empty();

  return true;
}
