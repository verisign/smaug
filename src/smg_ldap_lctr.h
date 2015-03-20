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


#ifndef _SMG_LDAP_LCTR_H
#define _SMG_LDAP_LCTR_H

#include <string>
#include "smg_smime_cert.h"
#include "smg_defs.h"


class SmgLdapLctr
{
  private:
    
    // Connection credentials for the email user 
    // eg., ldaps://1.2.3.4:636/CN=LastName\, FirstName,
    // OU=Users,OU=DC1,DC=vcorp,DC=ad,DC=myorg,DC=com
    std::string m_sConnectURI;
    std::string m_sConnectPassword;

    // server portion of the m_sConnectURI, 
    // ie ldaps://1.2.3.4:636
    std::string m_sHostAndPort;

    // Saved query URI, this keeps getting replaced along with the
    // results everytime a new query is spawned so it is the last 
    // query along with the results only, we do not store history
    std::string m_sQueryURI;

    // A list of userCertificate/userSMIMECertificate for query URI
    // passed into fetch(..) 
    SmgSmimeCertList_t  m_oSMIMECertificateList;   

    // add a SmgSmimeCert to the m_oSMIMECertificateList
    bool addCert(SmgSmimeCert* p_oCert);

    // clear out m_oSMIMECertificateList
    void clear();

    void copyHelper(const SmgLdapLctr &src, SmgLdapLctr &dst);
    bool parseHelper(std::string sTemp1, std::string &sHost,
                     int &port, std::string &sURI);

  public:
    SmgLdapLctr();
    virtual ~SmgLdapLctr();
 
    // Initializes to connect to an ldap server with credentials
    // and erases the previous state of the class 
    // the separation of init and construction enables the user to
    // reuse this class to connect to a different ldap server
    bool init(const std::string &sConnectURI, const std::string &sPassword);

    // Retrieves a list of certificates from the ldap server for m_sQueryURI
    // and populates m_oSMIMECertificateList
    bool fetch(const std::string &sQueryURI);

    // returns 'ldap'
    virtual std::string getName();

    virtual SmgLdapLctr duplicate();

    // return an iterator to the list of certificates
    virtual SmgSmimeCertKIter_t beginSMIMECertificateList() const;
    virtual SmgSmimeCertKIter_t endSMIMECertificateList() const;
    size_t numSMIMECertificates() const;

    virtual SmgLdapLctr &operator=(SmgLdapLctr const &p_oRHS);
};

#endif
