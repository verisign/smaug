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

#include "smg_ldap_lctr.h"

using namespace std;

// test app for validating that the SMIME certificates are returned 

void _usage()
{
  printf("test_smg_ldap_lptr [ <Connect_URI> <Password> <URI> ] | -h\n");
}

bool certListHelper(SmgLdapLctr& s)
{
    bool bRet = true;

    SmgSmimeCertKIter_t iterend = s.endSMIMECertificateList();
    for (SmgSmimeCertKIter_t iter = s.beginSMIMECertificateList(); iter != iterend; iter++)
    { 
       SmgSmimeCert *oCert = (SmgSmimeCert *) *iter;
       string sClearText = "This is a \n test...";
       SmgBytesVector_t oBytes(sClearText.begin(), sClearText.end());
       SmgBytesVector_t oCipherBytes;
       if (!oCert->encrypt(oBytes, oCipherBytes))
       {
          printf("FAIL: Encrypt failed\n");
          bRet = false;
       }
    }
    return bRet;
}
 
int main(int argc, char *argv[])
{
    bool bRet = true;
    if (argc != 4)
    {
        _usage();
        return 0;
    } 
    if (!strncmp("-h", argv[1], 2))
    {
        _usage();
        return 0;
    }

    // Check dynamic allocation
    SmgLdapLctr *sd = new SmgLdapLctr();
    if (sd->init(argv[3], argv[2]))
    {
        if (sd->fetch(argv[1]))
        {
           size_t uSizeCount = sd->numSMIMECertificates();
           if (!certListHelper(*sd))
           {
               printf("FAIL: Fetch failed\n");
               bRet = false;
           }
        }
    }
    delete sd;


    SmgLdapLctr s;

    if (s.init(argv[3], argv[2]))
    {
        if (s.fetch(argv[1]))
        { 
           size_t uSizeCount = s.numSMIMECertificates();
           if (!certListHelper(s))
           {
               printf("FAIL: Fetch failed\n");
               bRet = false;
           }
        }

        // repeat to make sure clear() works
        if (s.fetch(argv[1]))
        {
           if (!certListHelper(s))
           {
               printf("FAIL: fetch after clear failed\n");
               bRet = false;
           }
        }
    }

    SmgLdapLctr s1 = s.duplicate();
    if (!certListHelper(s1))
    {
        printf("FAIL: Duplicate failed\n");
        bRet = false;
    }

    SmgLdapLctr s2 = s;
    if (!certListHelper(s2))
    {
        printf("FAIL: Assignment failed\n");
        bRet = false;
    }
 
    if (true == bRet)
    {
      printf(">>>SUCCESS<<<\n");
    }
    else
    {  
      printf(">>>FAIL<<<\n");
    }

    return bRet;
}
