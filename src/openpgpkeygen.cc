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
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <iostream>
#include <string>

#include "smg_id.h"
#include "smg_pgp_association.h"

#ifndef NOERROR
#define NOERROR 0
#endif

using namespace std;

void _usage()
{
    fprintf(stdout, "openpgpkeygen [ <email address> ] | -h\n");
}

bool _menu(string &p_sEmail)
{
  bool bRet = false;

  char szOption[128] = {0};
  // int iOption = -1;

  memset(szOption, 0, 128);

  fprintf(stdout, "Enter email address > ");
  p_sEmail.clear();
  getline(std::cin, p_sEmail);

  bRet = true;

  return bRet;
}

int main(int argc, char *argv[])
{
  int iRet = 1;

  string sEmail;

  if ( argc > 2 )
  {
    _usage();
  }
  else
  {
    bool bOK = false;
    if (1 == argc)
    {
      bOK = _menu(sEmail);
    }
    else
    {
      if (0 == strncmp(argv[1], "-h", 2))
      {
        _usage();
      }
      else
      {
        sEmail = argv[1];
        errno = NOERROR;
        bOK = true;
      }
    }

    if (bOK)
    {
      SmgID oID;
      SmgPgpAssociation oAssoc;
      string sTxt;

      if (!oID.init(sEmail))
      {
        fprintf(stderr, "Unable to init ID.\n");
      }
      else if (!oAssoc.initLocal(sEmail))
      {
        fprintf(stderr, "Unable to init local association for email address '%s'.  Is there a key for this email in the local key ring?\n", sEmail.c_str());
      }
      else if (!oAssoc.toText(sTxt))
      {
        fprintf(stderr, "Unable to get text of association.\n");
      }
      else
      {
        fprintf(stdout, "%s IN TYPE%d %s;\n", oID.getPgpName().c_str(), SMG_OPENPGPKEY_RR_TYPE, sTxt.c_str());
      }
    }
  }

  return iRet;
}
