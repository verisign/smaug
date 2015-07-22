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
#include <cstring>

#ifndef _SMG_DEBUG
#define _SMG_DEBUG
#endif


#include "smg_smime_cert.h"

using namespace std;

void _usage()
{
  printf("test_smg_smime_cert [ <smime cert file (./smime.key)> ] | -h\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sCertFile = "./smime.key";

  if (argc > 1)
  {
    if (0 == strncmp(argv[1], "-h", 2))
    {
      _usage();
      iRet = 0;
    }
    else
    {
      sCertFile = argv[1];
    }
  }

  for (int i = 0; i < 10; i++)
  {
  if (0 != iRet)
  {
    string sClearText = "This is a \n test...";
    SmgBytesVector_t oBytes(sClearText.begin(), sClearText.end());
    SmgBytesVector_t oBytes2(sClearText.begin(), sClearText.end());
    string sSigText;
    SmgBytesVector_t oSigBytes;
    string sCipherText;
    SmgBytesVector_t oCipherBytes;
    SmgBytesVector_t oClearBytes;
    SmgBytesVector_t oHash;
    string sHash;

    SmgSmimeCert oCert;

    if (!oCert.initFromFile(sCertFile))
    {
      // fprintf(stderr, "Unable to initialize with file '%s'\n", sCertFile.c_str());
      smg_log("Unable to initialize with file '%s'\n", sCertFile.c_str());
    }
    /*
    else if (!oCert.sign(oBytes, sSigText))
    {
      fprintf(stderr, "Unable to sign text '%s'\n", sClearText.c_str());
    }
    else if (!oCert.verify(SmgBytesVector_t(sSigText.begin(), sSigText.end())))
    {
      fprintf(stderr, "Unable to verify signature: '%s'\n", sSigText.c_str());
    }
    else if (!oCert.encrypt(SmgBytesVector_t(sClearText.begin(), sClearText.end()), oCipherText))
    {
      fprintf(stderr, "Unable to encrypt clear text '%s'\n", sClearText.c_str());
    }
    else if (!oCert.decrypt(sCipherText, oClearBytes))
    {
      fprintf(stderr, "Unable to decrypt cipher text: '%s'\n", sCipherText.c_str());
    }
    */
    else if (!oCert.sign(oBytes, oSigBytes))
    {
      fprintf(stderr, "Unable to sign text '%s'\n", sClearText.c_str());
    }
    else if (!oCert.verify(oSigBytes))
    {
      fprintf(stderr, "Unable to verify signature: '%s'\n", oSigBytes.data());
    }
    else if (!oCert.encrypt(oBytes, oCipherBytes))
    {
      fprintf(stderr, "Unable to encrypt clear text '%s'\n", oBytes.data());
    }
    else if (!oCert.decrypt(oCipherBytes, oClearBytes))
    {
      fprintf(stderr, "Unable to decrypt cipher text: '%s'\n", oCipherBytes.data());
    }
    else
    {
      bool bOK = true;
      for (int i = 0; bOK && i <= SEL_SPKI; i++)
      {
        for (int j = 0; bOK && j <= MAT_SHA512; j++)
        {
          if (!(bOK = oCert.calcCertAssocData((SmgSelector_e) i, (SmgMatching_e) j, oHash)))
          {
            fprintf(stderr, "Unable to calc binary form of cert's hash for %d %d\n", i, j);
          }
          else if (!(bOK = oCert.calcCertAssocData((SmgSelector_e) i, (SmgMatching_e) j, sHash)))
          {
            fprintf(stderr, "Unable to calc string form of cert's hash for %d %d\n", i, j);
          }
          else
          {
            fprintf(stdout, "Cert Hash for %d %d has %lu bytes and is %s\n", 
                    i, 
                    j, 
                    oHash.size(),
                    sHash.c_str());
          }
        }
      }

      oCert.clear();
      iRet = (bOK) ? 0 : 1;
    }
  }
  }

  if (0 == iRet)
  {
    printf(">>>SUCCESS<<<\n");
  }
  else
  {
    printf(">>>FAIL<<<\n");
  }

  return iRet;
}
