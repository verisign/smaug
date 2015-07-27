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
#include <errno.h>
#include <unistd.h>
#include <locale.h>

#include <gpgme.h>
#include <gpg-error.h>

#include <fstream>
#include <sstream>

#include <cstring>

#include "smg_pgp_key.h"

using namespace std;

SmgPgpKey::SmgPgpKey()
  : m_bInit(false),
    m_pPubKeyBuf(NULL),
    m_uPubKeyBufLen(0),
    m_pGpgmeCtx(NULL),
    m_pPubKey(NULL)
{

}

SmgPgpKey::~SmgPgpKey()
{
  clear();
}

bool SmgPgpKey::init(SmgBytesVector_t &p_oBytes, const char *p_szHomeDir /*= NULL*/)
{
  string sHomeDir = (NULL == p_szHomeDir) ? "" : p_szHomeDir;

  return init(p_oBytes, sHomeDir);
}

bool SmgPgpKey::init(SmgBytesVector_t &p_oBytes, std::string &p_sHomeDir)
{
  bool bRet = false;

  clear();
  
  gpg_error_t tErr;
  m_sHomeDir = p_sHomeDir;

  if (!primeGpgme())
  {
    smg_log("Unable to prime GPGME engine.\n");
  }
  else
  {
    if (p_oBytes.size() > 0)
    {
      gpgme_data_t pBuff = NULL;
      gpgme_import_result_t pImportResult = NULL;
      if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new_from_mem(&pBuff, (const char *) p_oBytes.data(), p_oBytes.size(), 0)))
      {
        smg_log("Unable to create memory buffer: [%d] %s\n", tErr, gpgme_strerror(tErr));
      }
      else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_import(m_pGpgmeCtx, pBuff)))
      {
        smg_log("Unable to imoprt key from data buff: %s\n", gpgme_strerror(tErr));
      }
      else
      {
        m_pPubKeyBuf = gpgme_data_release_and_get_mem(pBuff, &m_uPubKeyBufLen);
        if (NULL == (pImportResult = gpgme_op_import_result(m_pGpgmeCtx)))
        {
          smg_log("Unable to get result for key import.\n");
        }
        else if (1 != pImportResult->considered)
        {
          smg_log("Expecting 1 key to be considered for import, but got %d\n", pImportResult->considered);
        }
        else if (NULL == pImportResult->imports->fpr)
        {
          smg_log("Got a NULL fingerprint for imported key.\n");
        }
        else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_keylist_start(m_pGpgmeCtx, pImportResult->imports->fpr, 0)))
        {
          smg_log("Unable to get public key '%s' that was just imported: %s\n", pImportResult->imports->fpr, gpgme_strerror(tErr));
        }
        else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_keylist_next(m_pGpgmeCtx, &m_pPubKey)))
        {
          smg_log("Unable to export the actual key for '%s' that was just imported: %s\n", pImportResult->imports->fpr, gpgme_strerror(tErr));
        }
        else
        {
          m_sKeyFingerprint = pImportResult->imports->fpr;
          smg_log("Initialized public key.\n");
          bRet = true;
          m_bInit = true;
        }
      }
    }
  }

  return bRet;
}

bool SmgPgpKey::init(uint8_t *p_pBytes, 
                        size_t p_uBytesLen)
{
  bool bRet = false;

  if (NULL == p_pBytes)
  {
    smg_log("Unable to init with NULL bytes.\n");
  }
  else if (0 == p_uBytesLen)
  {
    smg_log("Unable to init with 0 bytes.\n");
  }
  else
  {
    SmgBytesVector_t oVec(p_pBytes, p_pBytes + p_uBytesLen);

    bRet = init(oVec);
  }

  return bRet;
}

bool SmgPgpKey::initLocal(std::string &p_sID, const char *p_szHomeDir /*= NULL*/)
{
  string sHomeDir;
  if (NULL != p_szHomeDir)
  {
    sHomeDir = p_szHomeDir;
  }

  return initLocal(p_sID, sHomeDir);
}

bool SmgPgpKey::initLocal(std::string &p_sID, std::string &p_sHomeDir)
{
  bool bRet = false;

  gpgme_error_t tErr;
  /*
  const char *szVersion = NULL;
  szVersion = gpgme_check_version(NULL);
  setlocale(LC_ALL, "");
  gpg_err_init();
  gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
  gpgme_engine_info_t pEngInfo = NULL;
  const char *szProto = NULL;

  if (NULL != m_pGpgmeCtx)
  {
    gpgme_release(m_pGpgmeCtx);
    m_pGpgmeCtx = NULL;
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("GPG engine doesn't seem to support OpenPGP protocol: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_new(&m_pGpgmeCtx)))
  {
    smg_log("Unable to get GPG context: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_set_protocol(m_pGpgmeCtx, GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("Unable to set protocol to OpenPGP: '%s'\n", gpg_strerror(tErr));
  }
  else if (NULL == (szProto = gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("Unable to get protocol name, but protocol exists for OpenPGP?\n");
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_get_engine_info(&pEngInfo)))
  {
    smg_log("Unable to get engine info: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_ctx_set_engine_info(m_pGpgmeCtx,
                                                                 GPGME_PROTOCOL_OpenPGP,
                                                                 pEngInfo->file_name,
                                                                 (m_sHomeDir == "") ? pEngInfo->home_dir : m_sHomeDir.c_str())))
  {
    smg_log("Unable to set engine info in context: '%s'\n", gpg_strerror(tErr));
  }
  */

  clear();

  if (!primeGpgme())
  {
    smg_log("Unable to prime GPGME engine.\n");
  }
  else
  {
    gpgme_key_t tKey;
    gpgme_data_t pPubKey;
    // tErr = gpgme_get_key(m_pGpgmeCtx, p_sID.c_str(), &tKey, 1);
    tErr = gpgme_op_keylist_start(m_pGpgmeCtx, p_sID.c_str(), 1);
    // tErr = gpgme_op_keylist_start(m_pGpgmeCtx, NULL, 1);

    if (GPG_ERR_NO_ERROR != tErr)
    {
      smg_log("Error while getting key with ID: '%s' as UID: %d: [%d] %s\n", p_sID.c_str(), getuid(), tErr, gpgme_strerror(tErr));
    }
    else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_keylist_next(m_pGpgmeCtx, &tKey)))
    {
      smg_log("Error unable to find next key for ID: '%s': [%d] %s\n", p_sID.c_str(), tErr, gpgme_strerror(tErr));
    }
    else if (0 != (tErr = gpgme_signers_add(m_pGpgmeCtx, tKey)))
    {
      smg_log("Error while adding signer key for ID: '%s': [%d] %s\n", p_sID.c_str(), tErr, gpgme_strerror(tErr));
      gpgme_key_unref(tKey);
    }
    else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_keylist_start(m_pGpgmeCtx, p_sID.c_str(), 0)))
    {
      smg_log("Error while getting public key with ID: '%s' as UID: %d: [%d] %s\n", p_sID.c_str(), getuid(), tErr, gpgme_strerror(tErr));
    }
    else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_keylist_next(m_pGpgmeCtx, &m_pPubKey)))
    {
      smg_log("Error unable to find next public key for ID: '%s': [%d] %s\n", p_sID.c_str(), tErr, gpgme_strerror(tErr));
    }
    else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pPubKey)))
    {
      smg_log("Unable to allocate public key buffer '%s'\n", gpgme_strerror(tErr));
      gpgme_key_unref(tKey);
    }
    else if (0 != (tErr = gpgme_op_export(m_pGpgmeCtx, p_sID.c_str(), GPGME_EXPORT_MODE_MINIMAL, pPubKey)))
    {
      smg_log("Unable to get public key (min export) for '%s': [%d] %s\n", p_sID.c_str(), tErr, gpgme_strerror(tErr));
      gpgme_key_unref(tKey);
    }
    else if (NULL == (m_pPubKeyBuf = gpgme_data_release_and_get_mem(pPubKey, &m_uPubKeyBufLen)))
    {
      smg_log("Unable to get internal buffer for public key: [%d] %s\n", tErr, gpgme_strerror(tErr));
      gpgme_key_unref(tKey);
    }
    else
    {
      m_sID = p_sID;
      m_sHomeDir = p_sHomeDir;
      gpgme_set_armor(m_pGpgmeCtx, 1);
      gpgme_key_unref(tKey);
      bRet = true;
      m_bInit = true;
    }
  }

  return bRet;
}

bool SmgPgpKey::clear()
{
  m_bInit = false;

  if (NULL != m_pGpgmeCtx)
  {
    gpgme_signers_clear(m_pGpgmeCtx);
    gpgme_release(m_pGpgmeCtx);
    m_pGpgmeCtx = NULL;
  }

  if (NULL != m_pPubKeyBuf)
  {
    gpgme_free(m_pPubKeyBuf);
    m_pPubKeyBuf = NULL;
    m_uPubKeyBufLen = 0;
  }

  if (NULL != m_pPubKey)
  {
    gpgme_key_unref(m_pPubKey);
    m_pPubKey = NULL;
  }

  m_sID = "";
  m_sHomeDir = "";

  return true;
}

uint8_t *SmgPgpKey::getBytes()
{
  return (uint8_t *) m_pPubKeyBuf;
}

size_t SmgPgpKey::getBytesLen()
{
  return m_uPubKeyBufLen;
}

bool SmgPgpKey::verify(SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  ssize_t lRet = 0;
  size_t uDataSize = p_oBytes.size();
  gpgme_error_t tErr;
  gpgme_data_t pData = NULL;
  gpgme_data_t pPlain = NULL;
  gpgme_verify_result_t pResult = NULL;

  if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pData)))
  {
    smg_log( "Unable to create data buffer: '%s'\n", gpgme_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pPlain)))
  {
    smg_log( "Unable to create plain text buffer: '%s'\n", gpgme_strerror(tErr));
  }
  else if (-1 == (lRet = gpgme_data_write(pData, p_oBytes.data(), uDataSize))
           || uDataSize != (size_t) lRet
           || 0 != (lRet = gpgme_data_seek(pData, 0, SEEK_SET)))
  {
    smg_log( "Unable to write data data: %lu: %s\n", lRet, strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_verify(m_pGpgmeCtx, pData, NULL, pPlain)))
  {
    smg_log( "Unable to verify: '%s'\n!>'%s'\n",
            gpg_strerror(tErr),
            p_oBytes.data());
  }
  else if (NULL == (pResult = gpgme_op_verify_result(m_pGpgmeCtx)))
  {
    smg_log( "Unable to get result object.\n");
  }
  else if (NULL == pResult->signatures)
  {
    smg_log( "Unable to get result signature object.\n");
  }
  else if (GPG_ERR_NO_ERROR != pResult->signatures->status)
  {
    smg_log( "Signature was invalid: %s\n", gpg_strerror(pResult->signatures->status));
  }
  else
  {
    smg_log( "Valid signature.\n");
    bRet = true;
  }

  if (NULL != pData)
  {
    gpgme_data_release(pData);
  }
  if (NULL != pPlain)
  {
    gpgme_data_release(pPlain);
  }
  return bRet;
}

bool SmgPgpKey::encrypt(SmgBytesVector_t &p_oBytes,
                 SmgBytesVector_t &p_oEncryptedBytes)
{
  bool bRet = false;

  ssize_t lRet = 0;
  size_t uDataSize = p_oBytes.size();
  off_t uCurr = 0;
  gpgme_error_t tErr;
  gpgme_data_t pData = NULL;
  gpgme_data_t pEnc = NULL;
  // gpgme_encrypt_result_t pResult = NULL;
  gpgme_key_t pEncKeys[2] = {m_pPubKey, NULL};

  if (!m_bInit)
  {
    smg_log("Key is not initialized.\n");
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pData)))
  {
    smg_log( "Unable to create data buffer: '%s'\n", gpgme_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pEnc)))
  {
    smg_log( "Unable to create cipher text buffer: '%s'\n", gpgme_strerror(tErr));
  }
  else if (-1 == (lRet = gpgme_data_write(pData, p_oBytes.data(), uDataSize))
           || uDataSize != (size_t) lRet
           || 0 != (lRet = gpgme_data_seek(pData, 0, SEEK_SET)))
  {
    smg_log( "Unable to write data data: %lu: %s\n", lRet, strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_encrypt(m_pGpgmeCtx, pEncKeys, GPGME_ENCRYPT_ALWAYS_TRUST, pData, pEnc)))
  {
    smg_log( "Unable to encrypt: '%s'\n!>'%s'\n",
            gpg_strerror(tErr),
            p_oBytes.data());
  }
  else if (0 >= (uCurr = gpgme_data_seek(pEnc, 0, SEEK_CUR)))
  {
    smg_log("Unable to get length of cipher text: %s\n", strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_seek(pEnc, 0, SEEK_SET)))
  {
    smg_log("Unable to rewind cipher text: %s\n", gpgme_strerror(tErr));
  }
  else
  {
    char *pBuff = new char[uCurr + 1];
    memset(pBuff, 0, uCurr + 1);
    if (0 >= (lRet = gpgme_data_read(pEnc, pBuff, uCurr)))
    {
      smg_log("Unable to read cipher text into buffer: %s\n", strerror(lRet));
    }
    else
    {
      p_oEncryptedBytes.assign(pBuff, pBuff + uCurr);
      smg_log("Encrypted...\n");
      bRet = true;
    }

    delete[] pBuff;
  }

  if (NULL != pData)
  {
    gpgme_data_release(pData);
  }
  if (NULL != pEnc)
  {
    gpgme_data_release(pEnc);
  }

  return bRet;
}

bool SmgPgpKey::encrypt(SmgBytesVector_t &p_oBytes,
                 std::string &p_sEncrypted)
{
  SmgBytesVector_t oEncBytes;
  bool bRet = encrypt(p_oBytes, oEncBytes);
  p_sEncrypted.assign((char *) oEncBytes.data(), oEncBytes.size());
#ifdef SMG_DEBUG
  if (bRet)
  {
    smg_log("Took in clear-text: %s\n", (char *) p_oBytes.data());
    smg_log("Converted to buffer:\n%s\n", p_sEncrypted.c_str());
  }
#endif

  return bRet;
}

bool SmgPgpKey::encrypt(std::string &p_sClear,
                           std::string &p_sEncrypted)
{
  SmgBytesVector_t oClearBytes(p_sClear.c_str(), p_sClear.c_str() + p_sClear.size());
  SmgBytesVector_t oEncBytes;
smg_log("Took %lu clear bytes in, and moved them to %lu clear bytes\n", p_sClear.size(), oClearBytes.size());
  bool bRet = encrypt(oClearBytes, oEncBytes);
  if (bRet)
  {
    p_sEncrypted.assign((char *) oEncBytes.data(), oEncBytes.size());
#ifdef SMG_DEBUG
    smg_log("Took in clear-text: %s\n", (char *) p_sClear.c_str());
    smg_log("Converted to buffer:\n%s\n", p_sEncrypted.c_str());
#endif
  }

  return bRet;
}

bool SmgPgpKey::decrypt(SmgBytesVector_t &p_oEncryptedBytes,
                 SmgBytesVector_t &p_oBytes)
{
  bool bRet = false;

  ssize_t lRet = 0;
  size_t uEncLen = p_oEncryptedBytes.size();
  off_t uCurr = 0;
  gpgme_error_t tErr = 0;
  gpgme_data_t pPlain = NULL;
  gpgme_data_t pEnc = NULL;
  gpgme_decrypt_result_t pDecResult = NULL;

  if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pPlain)))
  {
    smg_log("Unable to create new data buffer: %s\n", gpgme_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pEnc)))
  {
    smg_log("Unable to create new sig buffer: %s\n", gpgme_strerror(tErr));
  }
  else if (-1 == (lRet = gpgme_data_write(pEnc, p_oEncryptedBytes.data(), uEncLen))
           || lRet != uEncLen
           || 0 != gpgme_data_seek(pEnc, 0, SEEK_SET))
  {
    smg_log("Unable to copy data into buffer and rewind: %lu != %lu: %s\n", lRet, uEncLen, strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_decrypt(m_pGpgmeCtx, pEnc, pPlain)))
  {
    smg_log("Unable to decrypt data: %s\n", gpgme_strerror(tErr));
    if (NULL == (pDecResult = gpgme_op_decrypt_result(m_pGpgmeCtx)))
    {
      smg_log("Unable to get sign's result object.\n");
    }
    else
    {
      if (NULL != pDecResult->unsupported_algorithm)
      {
        smg_log("Unsupported Alg: %s\n", pDecResult->unsupported_algorithm);
      }

      if (pDecResult->wrong_key_usage)
      {
        smg_log( "Decryption failed because of wrong key usage.\n");
      }
    }
  }
  else if (0 >= (uCurr = gpgme_data_seek(pPlain, 0, SEEK_CUR)))
  {
    smg_log("Unable to get length of decrypted text: %s\n", strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_seek(pPlain, 0, SEEK_SET)))
  {
    smg_log("Unable to rewind plain text: %s\n", gpgme_strerror(tErr));
  }
  else
  {
    char *pBuff = new char[uCurr + 1];
    memset(pBuff, 0, uCurr + 1);
    if (0 >= (lRet = gpgme_data_read(pPlain, pBuff, uCurr)))
    {
      smg_log("Unable to read plain text into buffer: %s\n", strerror(lRet));
    }
    else
    {
      p_oBytes.assign(pBuff, pBuff + uCurr);
      bRet = true;
    }

    delete[] pBuff;
  }

  if (NULL != pPlain)
  {
    gpgme_data_release(pPlain);
  }
  if (NULL != pEnc)
  {
    gpgme_data_release(pEnc);
  }
  return bRet;
}

bool SmgPgpKey::decrypt(std::string &p_sEncrypted,
                 SmgBytesVector_t &p_oBytes)
{
  SmgBytesVector_t oEncBytes(p_sEncrypted.c_str(), p_sEncrypted.c_str() + p_sEncrypted.size());
  bool bRet = decrypt(oEncBytes, p_oBytes);
#ifdef SMG_DEBUG
  if (bRet)
  {
    smg_log("Took in cipher-text: %s\n", p_sEncrypted.c_str());
    smg_log("Converted to %s", (char *) p_oBytes.data());
  }
#endif

  return bRet;
}

bool SmgPgpKey::sign(SmgBytesVector_t &p_oBytes,
              SmgBytesVector_t &p_oSignature)
{
  bool bRet = false;

  ssize_t lRet = 0;
  size_t uByteLen = p_oBytes.size();
  off_t uCurr = 0;
  gpgme_error_t tErr = 0;
  gpgme_data_t pPlain = NULL;
  gpgme_data_t pSig = NULL;
  // gpgme_sign_result_t pSigResult = NULL;
  // gpgme_sig_mode_t tMode = GPGME_SIG_MODE_NORMAL;
  gpgme_sig_mode_t tMode = GPGME_SIG_MODE_CLEAR;

  if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pPlain)))
  {
    smg_log("Unable to create new data buffer: %s\n", gpgme_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new(&pSig)))
  {
    smg_log("Unable to create new sig buffer: %s\n", gpgme_strerror(tErr));
  }
  else if (-1 == (lRet = gpgme_data_write(pPlain, p_oBytes.data(), uByteLen))
           || lRet != uByteLen
           || 0 != gpgme_data_seek(pPlain, 0, SEEK_SET))
  {
    smg_log("Unable to copy data into buffer and rewind: %lu != %lu: %s\n", lRet, uByteLen, strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_op_sign(m_pGpgmeCtx, pPlain, pSig, tMode)))
  {
    smg_log("Unable to sign data: %s\n", gpgme_strerror(tErr));
  }
  /*
  else if (NULL == (pSigResult = gpgme_op_sign_result(m_pGpgmeCtx)))
  {
    smg_log("Unable to get sign's result object.\n");
  }
  else if (NULL == pSigResult->signatures)
  {
    smg_log("Signature list is NULL in sig result.\n");
  }
  else if (GPG_ERR_NO_ERROR != pSigResult->signatures->status)
  {
    smg_log( "Signature was invalid: %s\n", gpg_strerror(pResult->signatures->status));
  }
  */
  else if (0 >= (uCurr = gpgme_data_seek(pSig, 0, SEEK_CUR)))
  {
    smg_log("Unable to get length of signature: %s\n", strerror(errno));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_seek(pSig, 0, SEEK_SET)))
  {
    smg_log("Unable to rewind signature: %s\n", gpgme_strerror(tErr));
  }
  else
  {
    char *pBuff = new char[uCurr + 1];
    memset(pBuff, 0, uCurr + 1);
    if (0 >= (lRet = gpgme_data_read(pSig, pBuff, uCurr)))
    {
      smg_log("Unable to read signature into buffer: %s\n", strerror(lRet));
    }
    else
    {
      p_oSignature.assign(pBuff, pBuff + uCurr);
      bRet = true;
    }

    delete[] pBuff;
  }

  if (NULL != pPlain)
  {
    gpgme_data_release(pPlain);
  }
  if (NULL != pSig)
  {
    gpgme_data_release(pSig);
  }

  return bRet;
}

bool SmgPgpKey::sign(SmgBytesVector_t &p_oBytes,
              std::string &p_sSignature)
{
  SmgBytesVector_t oSig;
  bool bRet = sign(p_oBytes, oSig);
  p_sSignature.assign((char *) oSig.data(), oSig.size());

  return bRet;
}

SmgPgpKey &SmgPgpKey::operator=(SmgPgpKey const &p_oRHS)
{
  clear();
  m_bInit = p_oRHS.m_bInit;

  if (m_bInit)
  {
    gpgme_error_t tErr;

    if (m_uPubKeyBufLen > 0)
    {
      gpgme_data_t pBuff = NULL;
      if (GPG_ERR_NO_ERROR != (tErr = gpgme_data_new_from_mem(&pBuff, p_oRHS.m_pPubKeyBuf, p_oRHS.m_uPubKeyBufLen, 1)))
      {
        smg_log("Unable to create memory buffer: [%d] %s\n", tErr, gpgme_strerror(tErr));
      }
      else
      {
        m_pPubKeyBuf = gpgme_data_release_and_get_mem(pBuff, &m_uPubKeyBufLen);
      }
    }
  }

  return *this;
}

bool SmgPgpKey::primeGpgme()
{
  bool bRet = false;

  gpgme_error_t tErr;
  const char *szVersion = NULL;
  szVersion = gpgme_check_version(NULL);
  setlocale(LC_ALL, "");
  gpg_err_init();
  gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

  gpgme_engine_info_t pEngInfo = NULL;
  const char *szProto = NULL;

  if (NULL != m_pGpgmeCtx)
  {
    gpgme_release(m_pGpgmeCtx);
    m_pGpgmeCtx = NULL;
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("GPG engine doesn't seem to support OpenPGP protocol: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_new(&m_pGpgmeCtx)))
  {
    smg_log("Unable to get GPG context: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_set_protocol(m_pGpgmeCtx, GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("Unable to set protocol to OpenPGP: '%s'\n", gpg_strerror(tErr));
  }
  else if (NULL == (szProto = gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP)))
  {
    smg_log("Unable to get protocol name, but protocol exists for OpenPGP?\n");
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_get_engine_info(&pEngInfo)))
  {
    smg_log("Unable to get engine info: '%s'\n", gpg_strerror(tErr));
  }
  else if (GPG_ERR_NO_ERROR != (tErr = gpgme_ctx_set_engine_info(m_pGpgmeCtx,
                                                                 GPGME_PROTOCOL_OpenPGP,
                                                                 pEngInfo->file_name,
                                                                 (m_sHomeDir == "") ? pEngInfo->home_dir : m_sHomeDir.c_str())))
  {
    smg_log("Unable to set engine info in context: '%s'\n", gpg_strerror(tErr));
  }
  else
  {
    smg_log("Initialized with GPGME protocol \"%s\", file: \"%s\", home: \"%s\"\n",
            szProto,
            pEngInfo->file_name,
            m_sHomeDir.c_str());
    bRet = true;
  }

  return bRet;
}
