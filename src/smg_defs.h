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

#ifndef _SMG_DEFS_H
#define _SMG_DEFS_H

#include <string>
#include <list>
#include <map>
#include <vector>

#include <inttypes.h>
#include <stdint.h>

class SmgSmimeAssociation;
class SmgID;
class SmgSmimeCert;

#define smg_log(X, ...) fprintf(stderr, "%s [%d] " X, __FILE__, __LINE__, ##__VA_ARGS__); fflush(stderr);

#define SMG_SMIMEA_MIN_LEN 1 + 1 + 1 + 0 + 0
#define SMG_SMIMEA_MAX_LEN 10000000
#define SMG_SMIMEA_MIN_TXT_LEN 2 + 1 + 1

#define SMG_SMIMEA_RR_TYPE 65514

typedef std::list< SmgSmimeAssociation * > SmgSmimeAssocList_t;
typedef SmgSmimeAssocList_t::iterator SmgSmimeAssocIter_t;
typedef SmgSmimeAssocList_t::const_iterator SmgSmimeAssocKIter_t;

typedef std::list< SmgSmimeCert * > SmgSmimeCertList_t;
typedef SmgSmimeCertList_t::iterator SmgSmimeCertIter_t;
typedef SmgSmimeCertList_t::const_iterator SmgSmimeCertKIter_t;

#define LDAP_SECURE_PORT 636
#define LDAP_PREFIX "ldap://"
#define LDAP_SECURE_PREFIX "ldaps://"
#define LDAP_REG_STRING "ldap"
#define LDAP_SECURE_STRING "ldaps"
#define LDAP_USER_CERT_NAME "userCertificate"
#define LDAP_USER_SMIME_CERT_NAME "userSMIMECertificate"


typedef struct
{
  time_t m_tExpiration;
  SmgID *m_pID;
} SmgIdTtl_t;

typedef struct __attribute__ ((__packed__))
{
  uint8_t m_uUsage;
  uint8_t m_uSelector;
  uint8_t m_uMatching;
  uint16_t m_uAccessLen;
  char m_pAccess[0];
  char m_pCertAssociationData[0];
} SmgSmimeaRR_t;

typedef std::map< std::string, SmgIdTtl_t > SmgIdMap_t;
typedef SmgIdMap_t::iterator SmgIdMapIter_t;

// typedef std::vector< unsigned char > SmgBytesVector_t;
// typedef std::vector< char > SmgBytesVector_t;
typedef std::vector< uint8_t > SmgBytesVector_t;
typedef SmgBytesVector_t::iterator SmgBytesIter_t;

typedef enum
{
  USG_PRE_INIT = -1,
  USG_PKIX_TA,
  USG_PKIX_EE,
  USG_DANE_TA,
  USG_DANE_EE,
  USG_REJECT,
  USG_PRIV
} SmgUsage_e;

typedef enum
{
  SEL_PRE_INIT = -1,
  SEL_FULL,
  SEL_SPKI,
  SEL_PRIV
} SmgSelector_e;

typedef enum
{
  MAT_PRE_INIT = -1,
  MAT_FULL,
  MAT_SHA256,
  MAT_SHA512,
  MAT_PRIV
} SmgMatching_e;

typedef enum
{
  ACT_PRE_INIT = -1,
  ACT_ENCR,
  ACT_SIGN
} SmgCryptAction_e;

typedef enum
{
  SMG_X509_PEM = 0,
  SMG_X509_DER
} SmgX509Encoding_e;


#endif
