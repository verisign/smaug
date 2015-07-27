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
#include <cstring>

#ifndef _SMG_DEBUG
#define _SMG_DEBUG
#endif


#include "smg_pgp_key.h"

using namespace std;

void _usage()
{
  printf("test_smg_pgp_key <PGP key name> | -h\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sKey;

  if (argc < 2)
  {
    fprintf(stderr, "Unable to run without key name\n");
    _usage();
    iRet = 0;
  }
  else
  {
    if (0 == strncmp(argv[1], "-h", 2))
    {
      _usage();
      iRet = 0;
    }
    else
    {
      sKey = argv[1];

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

      SmgPgpKey oKey;

      if (!oKey.initLocal(sKey))
      {
        // fprintf(stderr, "Unable to initialize with file '%s'\n", sCertFile.c_str());
        smg_log("Unable to initialize with key name '%s'\n", sKey.c_str());
      }
      else if (!oKey.sign(oBytes, oSigBytes))
      {
        fprintf(stderr, "Unable to sign text '%s'\n", sClearText.c_str());
      }
      else if (!oKey.verify(oSigBytes))
      {
        fprintf(stderr, "Unable to verify signature: '%s'\n", oSigBytes.data());
      }
      else if (!oKey.encrypt(oBytes, oCipherBytes))
      {
        fprintf(stderr, "Unable to encrypt clear text '%s'\n", oBytes.data());
      }
      else if (!oKey.decrypt(oCipherBytes, oClearBytes))
      {
        fprintf(stderr, "Unable to decrypt cipher text: '%s'\n", oCipherBytes.data());
      }
      else
      {
        iRet = 0;
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
