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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "smg_tbird.h"
#include "smg_id_cache.h"
#include "smg_id.h"
#include "smg_net.h"
#include "smg_smime_association.h"
#include "smg_smime_cert.h"
#include "smg_defs.h"

using namespace std;

extern "C" {

int init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile)
{
  return smg_init(p_szEmailAddr, p_szCertFilePath, p_szLogFile);
}

const char* hash_sha224(const char *p_szKey)
{
  return NULL;
}

const char* ds_encrypt(const char *p_szEmail, const char *p_pBuf)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to encrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to encrypt NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, ACT_ENCR, oID))
      {
        bFound = true;
      }
      else
      {
        uint32_t uTTL = 0;
        SmgNet oNet;
        if (!oID.init(sEmail))
        {
          smg_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          smg_log("Unable to initialize network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, ACT_ENCR, uTTL))
        {
          smg_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          oIdCache.addID(oID, ACT_ENCR, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numEncAssociations())
        {
          smg_log("Unable to encrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          // This is where we could choose a specific SMIMEA RR if we have a preference.
          // For now, we will just find the first one that fits our needs.
          SmgSmimeAssociation *pAssoc = *(oID.beginEncAssociations());
          SmgSmimeCert &oCert = pAssoc->getCert();

          if (!oCert.encrypt(sBody, sRet))
          {
            smg_log("Unable to encrypt.\n");
          }
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  return sRet.c_str();
}

const char* ds_decrypt(const char *p_szEmail, const char *p_pBuf)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, ACT_ENCR, oID))
      {
        smg_log("Unable to find ID for '%s'\n", sEmail.c_str());
      }
      else
      {
        if (0 >= oID.numEncAssociations())
        {
          smg_log("Unable to decrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          bool bDecrypted = false;
          for (SmgSmimeAssocKIter_t tIter = oID.beginEncAssociations();
               oID.endEncAssociations() != tIter;
               tIter++)
          {
            SmgSmimeAssociation *pAssoc = *tIter;
            SmgSmimeCert &oCert = pAssoc->getCert();
            SmgBytesVector_t oOut;

            if (oCert.decrypt(sBody, oOut))
            {
              bDecrypted = true;
              sRet.assign((char *) oOut.data(), oOut.size());
              break;
            }
          }
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  return sRet.c_str();
}

const char* ds_sign(const char *p_szEmail, const char *p_pBuf, const char *p_szCertFile)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to decrypt into a NULL buffer.\n");
    }
    else if (NULL == p_szCertFile)
    {
      smg_log("Unable to load NULL cert file.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;
      string sFile = p_szCertFile;

      SmgID oID;
      SmgSmimeCert oCert;
      SmgBytesVector_t oBytes(sBody.begin(), sBody.end());

      if (!oID.init(sEmail))
      {
        smg_log("Unable to init ID for '%s'\n", sEmail.c_str());
      }
      else if (!oCert.initFromFile(sFile))
      {
        smg_log("Unable to init from file '%s'\n", sFile.c_str());
      }
      else if (!oCert.sign(oBytes, sRet))
      {
        smg_log("Unable to sign with ID '%s' from file '%s'\n", sEmail.c_str(), sFile.c_str());
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  return sRet.c_str();
}

const char* ds_sign2(const char *p_szEmail, const char *p_pBuf)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgSmimeCert oCert;
      SmgBytesVector_t oBytes(sBody.begin(), sBody.end());
      SmgIdCache &oIdCache = SmgIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, ACT_SIGN, oID))
      {
        smg_log("Unable to lookup ID for email '%s'\n", sEmail.c_str());
      }
      else if (oID.numSignAssociations() < 1)
      {
        smg_log("Unable to sign with no associations in ID '%s'\n", sEmail.c_str());
      }
      else
      {
        // This is where we could choose a specific SMIMEA RR if we have a preference.
        // For now, we will just find the first one that fits our needs.
        SmgSmimeAssociation *pAssoc = *(oID.beginSignAssociations());
        SmgSmimeCert &oCert = pAssoc->getCert();

        if (!oCert.sign(oBytes, sRet))
        {
          smg_log("Unable to sign with ID '%s'\n", sEmail.c_str());
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  return sRet.c_str();
}

int ds_verify(const char *p_szEmail, const char *p_pBuf)
{
  return smg_verify(p_szEmail, p_pBuf);
}

int ds_lookup(const char *p_szEmail, int p_iEnc)
{
  return smg_lookup(p_szEmail, p_iEnc);
}

int smg_init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile)
{
  int iRet = 0;
  const char *szRet = NULL;

  try
  {
    if (NULL != p_szLogFile && 0 < strlen(p_szLogFile))
    {
      dup(fileno(stderr));
      freopen(p_szLogFile,"w",stderr);
      dup2(fileno(stderr), fileno(stdout));
    }

    SmgIdCache &oCache = SmgIdCache::getInstance();
    SmgID oID;
    SmgSmimeAssociation oAssoc;

    if (NULL == p_szEmailAddr)
    {
      smg_log("Unable to load ID with NULL email address.\n");
      szRet = "Unable to load ID with NULL email address";
    }
    else if (NULL == p_szCertFilePath)
    {
      smg_log("Unable to load NULL file.\n");
      szRet = "Unable to load NULL file.";
    }
    else
    {
      string sEmail = p_szEmailAddr;
      string sFile = p_szCertFilePath;
      string sAccess;
      if (!oID.init(sEmail))
      {
        smg_log("Unable to initialized ID with email '%s'\n", sEmail.c_str());
        szRet = "Unable to initialized ID with email";
      }
      else if (!oAssoc.initFromFile(ACT_ENCR, USG_DANE_EE, SEL_FULL, MAT_FULL, sAccess, sFile))
      {
        smg_log("Unable to init cert, for encryption, from file '%s'\n", sFile.c_str());
        szRet = "Unable to init cert, for encryption, from file";
      }
      else if (!oID.addAssociation(oAssoc))
      {
        smg_log("Unable to add encryption association for file '%s'\n", sFile.c_str());
        szRet = "Unable to add encryption association for file ";
      }
      else if (!oAssoc.initFromFile(ACT_SIGN, USG_DANE_EE, SEL_FULL, MAT_FULL, sAccess, sFile))
      {
        smg_log("Unable to init cert, for signing, from file '%s'\n", sFile.c_str());
        szRet = "Unable to init cert, for signing, from file";
      }
      else if (!oID.addAssociation(oAssoc))
      {
        smg_log("Unable to add signing association for file '%s'\n", sFile.c_str());
        szRet = "Unable to add signing association for file ";
      }
      else if (!oCache.addID(oID, ACT_ENCR, 0))
      {
        smg_log("Unable to add ID to cache.\n");
        szRet = "Unable to add ID to cache.";
      }
      else if (!oCache.addID(oID, ACT_SIGN, 0))
      {
        smg_log("Unable to add ID to cache.\n");
        szRet = "Unable to add ID to cache.";
      }
      else
      {
smg_log("ADDED ID, '%s'\n", sEmail.c_str());
        iRet = 1;
      }
    }
  }
  catch (...)
  {
    smg_log("Caught exception.\n");
    szRet = "Caught exception.";
    iRet = 0;
  }

  return iRet;
  // return szRet;
}

// returns 1 == OK, 0 == ERR per CMS_verify
int smg_encrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to encrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to encrypt NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, ACT_ENCR, oID))
      {
        bFound = true;
      }
      else
      {
        uint32_t uTTL = 0;
        SmgNet oNet;
        if (!oID.init(sEmail))
        {
          smg_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          smg_log("Unable to initialize network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, ACT_ENCR, uTTL))
        {
          smg_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          oIdCache.addID(oID, ACT_ENCR, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numEncAssociations())
        {
          smg_log("Unable to encrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          // This is where we could choose a specific SMIMEA RR if we have a preference.
          // For now, we will just find the first one that fits our needs.
          SmgSmimeAssociation *pAssoc = *(oID.beginEncAssociations());
          SmgSmimeCert &oCert = pAssoc->getCert();

          if (!oCert.encrypt(sBody, sRet))
          {
            smg_log("Unable to encrypt.\n");
            sRet = "";
          }
          else
          {
            iRet = 1;
          }
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int smg_decrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, ACT_ENCR, oID))
      {
        smg_log("Unable to find ID for '%s'\n", sEmail.c_str());
      }
      else
      {
        if (0 >= oID.numEncAssociations())
        {
          smg_log("Unable to decrypt message to '%s' because no encryption associations found.\n", sEmail.c_str());
        }
        else
        {
          bool bDecrypted = false;
          for (SmgSmimeAssocKIter_t tIter = oID.beginEncAssociations();
               oID.endEncAssociations() != tIter;
               tIter++)
          {
            SmgSmimeAssociation *pAssoc = *tIter;
            SmgSmimeCert &oCert = pAssoc->getCert();
            SmgBytesVector_t oOut;

            if (oCert.decrypt(sBody, oOut))
            {
              bDecrypted = true;
              sRet.assign((char *) oOut.data(), oOut.size());
              iRet = 1;
              break;
            }
          }
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int smg_sign(const char *p_szEmail,   const char *p_pBuf, const char **p_pOutput)
{
  int iRet = 0;

  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  static string sRet;
  sRet = "";

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to decrypt email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to decrypt into a NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgSmimeCert oCert;
      SmgBytesVector_t oBytes(sBody.begin(), sBody.end());
      SmgIdCache &oIdCache = SmgIdCache::getInstance();

      if (!oIdCache.lookupSmimeID(sEmail, ACT_SIGN, oID))
      {
        smg_log("Unable to lookup ID for email '%s'\n", sEmail.c_str());
      }
      else if (oID.numSignAssociations() < 1)
      {
        smg_log("Unable to sign with no associations in ID '%s'\n", sEmail.c_str());
      }
      else
      {
        // This is where we could choose a specific SMIMEA RR if we have a preference.
        // For now, we will just find the first one that fits our needs.
        SmgSmimeAssociation *pAssoc = *(oID.beginSignAssociations());
        SmgSmimeCert &oCert = pAssoc->getCert();

        if (!oCert.sign(oBytes, sRet))
        {
          smg_log("Unable to sign with ID '%s'\n", sEmail.c_str());
          sRet = "";
        }
        else
        {
          iRet = 1;
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  *p_pOutput = sRet.c_str();

  return iRet;
}

int smg_verify(const char *p_szEmail, const char *p_pBuf)
{
  // This makes the function call non-thread safe, but the underlying library
  // IS thread safe.  Need to find a way to marry to the extension's 
  // string allocation model
  bool bVerified = false;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to verify email to NULL inbox.\n");
    }
    else if (NULL == p_pBuf)
    {
      smg_log("Unable to verify NULL buffer.\n");
    }
    else
    {
      string sEmail = p_szEmail;
      // The calling code in the plugin makes this a NULL terminated string.
      string sBody = p_pBuf;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();
      bool bFound = false;

      if (oIdCache.lookupSmimeID(sEmail, ACT_SIGN, oID))
      {
        bFound = true;
      }
      else
      {
        smg_log("Cache did not have entry for email '%s', fetching over DNS\n", sEmail.c_str());
        uint32_t uTTL = 0;
        SmgNet oNet;
        if (!oID.init(sEmail))
        {
          smg_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          smg_log("Unable to init network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, ACT_SIGN, uTTL))
        {
          smg_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          smg_log("Fetched SMIMEA for ID '%s', adding to cache with TTL %lu...\n", 
                  sEmail.c_str(), 
                  (unsigned long) uTTL);
          oIdCache.addID(oID, ACT_SIGN, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numSignAssociations())
        {
          smg_log("Unable to verify message to '%s' because no signing associations found.\n", sEmail.c_str());
        }
        else
        {
          SmgBytesVector_t oBytes(sBody.begin(), sBody.end());
          for (SmgSmimeAssocKIter_t tIter = oID.beginSignAssociations();
               oID.endSignAssociations() != tIter;
               tIter++)
          {
            SmgSmimeAssociation *pAssoc = *tIter;
            SmgSmimeCert &oCert = pAssoc->getCert();
            SmgBytesVector_t oOut;

            if (oCert.verify(oBytes))
            {
              bVerified = true;
              break;
            }
          }
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to encrypt, caught exception.\n");
  }

  return (int) bVerified;
}

int smg_lookup(const char *p_szEmail, int p_iEnc)
{
  int iRet = 0;

  try
  {
    if (NULL == p_szEmail)
    {
      smg_log("Unable to encrypt email to NULL inbox.\n");
    }
    else
    {
      string sEmail = p_szEmail;

      SmgID oID;
      SmgIdCache &oIdCache = SmgIdCache::getInstance();
      bool bFound = false;

      SmgCryptAction_e eAct = (p_iEnc) ? ACT_ENCR : ACT_SIGN;
      if (oIdCache.lookupSmimeID(sEmail, eAct, oID))
      {
        bFound = true;
      }
      else
      {
        smg_log("Cache did not have entry for email '%s', fetching over DNS\n", sEmail.c_str());

        uint32_t uTTL = 0;
        SmgNet oNet;
        if (!oID.init(sEmail))
        {
          smg_log("Unable to init ID with email '%s'\n", sEmail.c_str());
        }
        else if (!oNet.init())
        {
          smg_log("Unable to initialize network layer.\n");
        }
        else if (!oNet.lookupSmimeID(oID, eAct, uTTL))
        {
          smg_log("Unable to fetch SMIMEA for ID '%s'\n", sEmail.c_str());
        }
        else
        {
          smg_log("Fetched SMIMEA for ID '%s', adding to cache with TTL %lu...\n", 
                   sEmail.c_str(), 
                   (unsigned long) uTTL);
          oIdCache.addID(oID, eAct, uTTL);
          bFound = true;
        }
      }

      if (bFound)
      {
        if (0 >= oID.numEncAssociations())
        {
          smg_log("Lookup to '%s' failed, because no associations found.\n", sEmail.c_str());
        }
        else
        {
          iRet = 1;
        }
      }
    }
  }
  catch(...)
  {
    smg_log("Unable to lookup ID, caught exception.\n");
  }

  return iRet;
}


}
