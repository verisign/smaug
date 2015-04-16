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
#include <unistd.h>
#include <cstring>

#include "smg_id_cache.h"
#include "smg_id.h"

using namespace std;

void _usage()
{
  printf("test_smg_id_cache [ -h ]\n");
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  if (argc > 1)
  {
    if (strncmp("-h", argv[1], 2))
    {
      _usage();
      iRet = 0;
    }
  }

  if (1 == iRet)
  {
    string sEmailAddr = "user@example.com";
    string sTmpEmailAddr = "user2@example.com";

    SmgID oID;
    SmgID oTmpID;
    SmgID oQueryID;
    SmgIdCache &oCache = SmgIdCache::getInstance();

    fprintf(stdout, "Setting email to '%s'\n", sEmailAddr.c_str());
    if (!oID.init(sEmailAddr))
    {
      smg_log("Unable to initialize object.\n");
    }
    else if (!oTmpID.init(sTmpEmailAddr))
    {
      smg_log("Unable to initialize tmp object.\n");
    }
    else if (!oCache.addID(oID, ACT_ENCR, 0))
    {
      smg_log("Unable to add perma-ID.\n");
    }
    else if (!oCache.addID(oTmpID, ACT_SIGN, 1))
    {
      smg_log("Unable to add tmp-ID with 1 sec TTL.\n");
    }
    else if (!oCache.lookupSmimeID(sTmpEmailAddr, ACT_SIGN, oQueryID))
    {
      smg_log("UNable to lookup tmp-ID '%s'\n", sTmpEmailAddr.c_str());
    }
    else
    {
      fprintf(stdout, "Sleeping until tmp ID should be flushed.\n");
      sleep(2);

      if (!oCache.lookupSmimeID(sEmailAddr, ACT_ENCR, oQueryID))
      {
        smg_log("UNable to lookup perma-ID: '%s'\n", sEmailAddr.c_str());
      }
      else if (oCache.lookupSmimeID(sTmpEmailAddr, ACT_SIGN, oQueryID))
      {
        smg_log("WAS able to lookup tmp ID (after it hsould have been flushed.\n");
      }
      else
      {
        iRet = 0;
      }
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
