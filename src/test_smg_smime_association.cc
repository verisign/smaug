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

#include <fstream>

#include "smg_smime_association.h"

using namespace std;

void _usage()
{
  printf("test_smg_smime_association [ <cert file (./smime.crt)> ] | -h\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  const char *szFile = "./smime.crt";
  if (argc > 1)
  {
    szFile = argv[1];
  }

  for (int i = 0; i < 3; i++)
  {
  try
  {
    string sFile = szFile;
    string sAccess;
    /*
    ifstream oIF(szFile, std::ios::binary);
    SmgBytesVector_t oBytes((std::istreambuf_iterator<char>(oIF)),
                            std::istreambuf_iterator<char>());
    */

    fprintf(stdout, "Initializing 3 0 0 from file...\n");

    SmgSmimeAssociation oAssoc;

    if (!oAssoc.initFromFile(ACT_ENCR,
                             USG_DANE_EE,
                             SEL_FULL,
                             MAT_FULL,
                             sAccess,
                             sFile))
    {
      smg_log("Unable to init association.\n");
    }
    else if (!oAssoc.isInitialized())
    {
      smg_log("Should be initialized, but isn't\n");
    }
    else if (!oAssoc.isEncCert())
    {
      smg_log("Should be enc cert, but isn't\n");
    }
    else if (oAssoc.isSignCert())
    {
      smg_log("Should not be a sign assoc, but IS.\n");
    }
    else if (oAssoc.isRejectCert())
    {
      smg_log("Should NOT be a reject assoc, but is.\n");
    }
    else if (!oAssoc.isFullCert())
    {
      smg_log("Should be a full cert, but isn't.\n");
    }
    else if (oAssoc.isFingerprintCert())
    {
      smg_log("SHould not be a fingerprint assoc, but is.\n");
    }
    else if (oAssoc.isTA())
    {
      smg_log("Should not be a TA, but is.\n");
    }
    else if (oAssoc.isPKIX())
    {
      smg_log("Should not be a PKIX assoc, but is.\n");
    }
    else if (!oAssoc.isEE())
    {
      smg_log("SHould be an EE cert, but is NOT.\n");
    }
    else
    {
      fprintf(stdout, "Initial checks passed...\n");

      SmgBytesVector_t oOutVec;
      if (!oAssoc.toWire(oOutVec))
      {
        smg_log("Unable to convert association to bytes.\n");
      }
      else
      {
        fprintf(stdout, "Wire format is:\n");
        size_t uLen = oOutVec.size();
        uint8_t *pBuff = oOutVec.data();
        for (size_t u = 0; u < uLen && u < 60; u++)
        {
          fprintf(stdout, "  %02x", pBuff[u]);
        }
        if (uLen > 60)
        {
          fprintf(stdout, "...");
        }
        fprintf(stdout, "\n");

        SmgSmimeAssociation oAssoc2;
        SmgBytesVector_t oOutVec2;

        if (!(oAssoc2.fromWire(oAssoc.getAction(), oOutVec.data(), oOutVec.size())))
        {
          smg_log("Unable to initialize from wire.\n");
        }
        /*
        else if (!oAssoc2.setAction(oAssoc.getAction()))
        {
          smg_log("Unable to set action in assoc 2.\n");
        }
        */
        else if (!oAssoc2.isInitialized())
        {
          smg_log("reconstituted assoc is not initialized.\n");
        }
        else if (!oAssoc2.isEncCert()
                 || oAssoc2.isSignCert()
                 || oAssoc2.isRejectCert()
                 || !oAssoc2.isFullCert()
                 || oAssoc2.isFingerprintCert()
                 || oAssoc2.isTA()
                 || oAssoc2.isPKIX()
                 || !oAssoc2.isEE())
        {
          smg_log("reconstituded assoc is different than initial. . .\n");
        }
        else if (!oAssoc2.toWire(oOutVec2))
        {
          smg_log("Unable to serialize assoc2 toWire().\n");
        }
        else if (oOutVec != oOutVec2)
        {
          smg_log("Serialized vectors are not equal:\n");
          for (size_t u = 0; u < uLen; u++)
          {
            fprintf(stderr, "  %02x", pBuff[u]);
          }
          fprintf(stderr, "\n\t!=\n");
          uLen = oOutVec2.size();
          pBuff = oOutVec2.data();
          for (size_t u = 0; u < uLen; u++)
          {
            fprintf(stderr, "  %02x", pBuff[u]);
          }
          fprintf(stderr, "\n");
        }
        else
        {
          fprintf(stdout, "Checking text serialization...\n");

          string sOut;
          string sOut2;
          if (!oAssoc.toText(sOut))
          {
            smg_log("Unable to serialize to text.\n");
          }
          else
          {
            fprintf(stderr, "Serialized to:\n%s\n", sOut.c_str());

            if (!oAssoc2.fromText(oAssoc.getAction(), sOut))
            {
              smg_log("Unable to re-serialize from text.\n");
            }
            else if (!oAssoc2.toText(sOut2))
            {
              smg_log("Unable to serialize assoc 2 to text.\n");
            }
            else if (sOut != sOut2)
            {
              smg_log("Text serilaizations do not match:%s\n\t!=\n%s\n", sOut.c_str(), sOut2.c_str());
            }
            else
            {
              iRet = 0;
            }
          }
        }
      }
    }
  }
  catch (...)
  {
    smg_log("Caught unknown excpetion.\n");
    iRet = 1;
  }
  }

  if (0 == iRet)
  {
    fprintf(stderr, ">>>SUCCESS<<<\n");
  }
  else
  {
    fprintf(stderr, ">>>FAIL<<<\n");
  }
}
