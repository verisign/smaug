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
#include <fcntl.h>
#include <unistd.h>

#include "smg_smime_cert.h"
#include "smg_ldap_lctr.h"
#include "ldap.h"
#include "ldif.h"

using namespace std;

SmgLdapLctr::SmgLdapLctr()
  : m_sConnectURI(""),
    m_sConnectPassword(""),
    m_sQueryURI("")
{

}

SmgLdapLctr::~SmgLdapLctr()
{
  clear();
}

bool SmgLdapLctr::parseHelper(std::string sTemp1, std::string &sHost, 
                 int &port, std::string &sURI)
{
  bool bRet = true;

  size_t uPos = sTemp1.find(':');
  if (string::npos == uPos)
  {
    smg_log("Error: Host port separator not found in %s\n", sTemp1.c_str());
    bRet = false;
  } 
  else
  {
    sHost = sTemp1.substr(0, uPos);
    std::string sTemp = sTemp1.substr(uPos + 1);
    size_t uPos1 = sTemp.find('/');
    if (string::npos == uPos)
    {
      smg_log("Error: port URI separator not found in %s\n", sTemp1.c_str());
      bRet = false;
    } 
    else
    {
      port = atoi(sTemp.substr(0, uPos1).c_str());
      sURI = sTemp.substr(uPos1 + 1);
    }
  }
  return bRet;
}

bool SmgLdapLctr::init(const std::string &sConnectURI, const std::string &sPassword)
{
  bool bRet = true;
  int         port    = LDAP_SECURE_PORT;
  std::string sPrefix = LDAP_SECURE_PREFIX;
 
  if (!sConnectURI.length() || !sPassword.length())
  {
      smg_log("ERROR: Passing empty URI or password\n");
  }
  else 
  {
    std::string sHost;
    std::string sURI;
    if (sConnectURI.substr(0, 5) == LDAP_SECURE_STRING)
    {  
      std::string sTemp1 = sConnectURI.substr(8);
      parseHelper(sTemp1, sHost, port, sURI);
    }
    else if (sConnectURI.substr(0, 4) == LDAP_REG_STRING)
    {    
      sPrefix = LDAP_PREFIX;
      std::string sTemp1 = sConnectURI.substr(7);
      parseHelper(sTemp1, sHost, port, sURI);
    }  
    else 
    {
      smg_log("Protocol not recognized: %s\n", sConnectURI.c_str());
      bRet = false;
    }
    if (bRet)
    {
      m_sConnectURI = sURI;
  
      std::string sTmp = to_string(port);
      m_sHostAndPort = sPrefix + sHost;
      m_sHostAndPort += ":";
      m_sHostAndPort += sTmp;
   
      m_sConnectPassword = sPassword;
    }
  }
  return bRet;
}

void SmgLdapLctr::clear()
{
  // clear out the list of stale results before populating
  SmgSmimeCertKIter_t iterend = endSMIMECertificateList();
  for (SmgSmimeCertKIter_t iter = beginSMIMECertificateList(); iter != iterend; iter++)
  {
    if (*iter) delete *iter;
  }
  m_oSMIMECertificateList.erase(beginSMIMECertificateList(), 
                                endSMIMECertificateList());
}

// Return a list of all userCertificate userSMIMECertificate
bool SmgLdapLctr::fetch(const std::string &sQueryURI)
{
  LDAP         *ld = NULL;
  LDAPMessage  *result = NULL, *e = NULL;
  BerElement   *ber = NULL;
  int          i, rc;
  struct berval  bv, *bvals = NULL, **bvp = &bvals;
  int iProtocol = LDAP_VERSION3;
  bool bRet = true;

  clear();

  m_sQueryURI = sQueryURI;

  /* Open LDAP Connection */
  if( ldap_initialize( &ld, m_sHostAndPort.c_str() ) )
  {
    smg_log( "ERROR: failed ldap_initialize" );
    bRet = false;
  }  
  else if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &iProtocol )
           != LDAP_OPT_SUCCESS )
  {
    smg_log("ERROR: Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
              iProtocol );
    bRet = false;
  }
  else 
  {
  
    rc = ldap_simple_bind_s( ld, m_sConnectURI.c_str(), m_sConnectPassword.c_str());
    if (rc != LDAP_SUCCESS ) 
    {
      smg_log("ERROR: failure of ldap_simple_bind_s: %s\n", ldap_err2string(rc));
      bRet = false;
    }
    else
    {
      /* Search for the SMIME Certificates. */
      char* attrs[] = {LDAP_USER_CERT_NAME, NULL};
      // TODO: add support in SmgSmimeCert for userSmimeCertificate
      // char* attrs[] = {LDAP_USER_CERT_NAME, LDAP_USER_SMIME_CERT_NAME, NULL};
      if ((rc = ldap_search_ext_s( ld, sQueryURI.c_str(), LDAP_SCOPE_BASE,
         "(objectclass=*)",  attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
         LDAP_NO_LIMIT, &result ) ) != LDAP_SUCCESS ) 
      {
        smg_log("ERROR: ldap_search_ext_s: %s\n", ldap_err2string(rc));
        bRet = false;
      }
      else 
      {
        e = ldap_first_entry( ld, result );
        if ( e != NULL ) 
        {

          rc = ldap_get_dn_ber( ld, e, &ber, &bv );
          if (rc == LDAP_SUCCESS)
          {
            for (rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
                 rc == LDAP_SUCCESS;
                 rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp ) )
            {
              if (bv.bv_val == NULL) break;
              if ( bvals ) 
              {
                for ( i = 0; bvals[i].bv_val != NULL; i++ )
                {
                  SmgSmimeCert *oCert = new SmgSmimeCert; 
                  if (strcmp(bv.bv_val, "userSMIMECertificate") == 0)
                    ; // TODO: oCert->init((uint8_t *)bvals[i].bv_val, bvals[i].bv_len, SMG_PKCS7_ENC);
                  else 
                    oCert->init((uint8_t *)bvals[i].bv_val, bvals[i].bv_len, SMG_X509_DER); 
                  addCert(oCert);
                }
              }
            } 
            if ( ber != NULL ) 
            {
              ber_free( ber, 0 );
            }
          }
        }
      } 
    } 
    ldap_msgfree( result );
    ldap_unbind( ld );
  }
  return bRet;;
}

std::string SmgLdapLctr::getName()    
{
  return "ldap";
}

void SmgLdapLctr::copyHelper(const SmgLdapLctr &src, SmgLdapLctr &dst)
{
  dst.m_sConnectURI      = src.m_sConnectURI;
  dst.m_sConnectPassword = src.m_sConnectPassword;
  dst.m_sHostAndPort     = src.m_sHostAndPort;
  dst.m_sQueryURI        = src.m_sQueryURI;
  SmgSmimeCertKIter_t iterend = src.endSMIMECertificateList();
  for (SmgSmimeCertKIter_t iter = src.beginSMIMECertificateList(); 
       iter != iterend; iter++)
  { 
    SmgSmimeCert *oCert = new SmgSmimeCert;
    oCert = (SmgSmimeCert *)*iter;
    dst.addCert(oCert);
  }
}

SmgLdapLctr SmgLdapLctr::duplicate()
{
  SmgLdapLctr *pResult = new SmgLdapLctr();
  copyHelper(*this, *pResult);
  return *pResult;
}

bool SmgLdapLctr::addCert(SmgSmimeCert* p_oCert)
{
  m_oSMIMECertificateList.push_back(p_oCert);
  return true;
}

SmgSmimeCertKIter_t SmgLdapLctr::beginSMIMECertificateList() const
{
  return m_oSMIMECertificateList.begin();
}

SmgSmimeCertKIter_t SmgLdapLctr::endSMIMECertificateList() const
{
  return m_oSMIMECertificateList.end();
}

size_t SmgLdapLctr::numSMIMECertificates() const
{
  return m_oSMIMECertificateList.size();
}

SmgLdapLctr &SmgLdapLctr::operator=(SmgLdapLctr const &p_oRHS)
{
  clear();
  copyHelper(p_oRHS, *this);

  return *this;
}
