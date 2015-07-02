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

#include "smg_net.h"
#include "smg_id.h"
#include "smg_smime_association.h"

using namespace std;

void _usage()
{
  fprintf(stdout, "test_smg_net [ <domain name of SMIMEA RR> ] | -h\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sName = "user@example.com";

  if (argc > 1)
  {
    sName = argv[1];
  }

  if (sName == "-h")
  {
    _usage();
    iRet = 0;
  }
  else
  {
    SmgNet oNet;
    SmgID oID;
    uint32_t uTTL = 0;

    if (!oNet.init())
    {
      fprintf(stderr, "Unable to init SmgNet object.\n");
    }
    else if (!oID.init(sName))
    {
      fprintf(stderr, "Unable to init SmgID object with name '%s'.\n", sName.c_str());
    }
    else if (!oNet.lookupSmimeID(oID, ACT_ENCR))
    {
      fprintf(stderr, "Unable to lookup smime key for '%s' at '%s'\n", sName.c_str(), oID.getSmimeName().c_str());
    }
    else if (!oNet.lookupSmimeID(oID, ACT_SIGN, uTTL))
    {
	fprintf(stderr, "Unable to lookup smime key for '%s' at '%s'\n", sName.c_str(), oID.getSmimeName().c_str());
    }
    
    else if (oID.numAssociations() != 1)
    {
      fprintf(stderr, "Got the wrong number of associations.  Expected 1, got %lu\n", oID.numAssociations());
    }
    else
    {
      fprintf(stdout, "Got a TTL of %u for:\n%s\n", uTTL, oID.getSmimeName().c_str());
      SmgSmimeAssocKIter_t tIter;
      for (tIter = oID.beginAssociations();
           oID.endAssociations() != tIter;
           tIter++)
      {
        string sTxt;
        (*tIter)->toText(sTxt);
        fprintf(stdout, "\t%s\n", sTxt.c_str());
      }

      fprintf(stdout, "%s\n", oID.getSmimeName().c_str());
      for (tIter = oID.beginAssociations();
           oID.endAssociations() != tIter;
           tIter++)
      {
        string sTxt;
        (*tIter)->toText(sTxt);
        fprintf(stdout, "\t%s\n", sTxt.c_str());
      }
      iRet = 0;
    }
  }

  if (0 == iRet)
  {
    fprintf(stdout, ">>>SUCCESS<<<\n");
  }
  else
  {
    fprintf(stdout, ">>>FAIL<<<\n");
  }

  return iRet;
}
