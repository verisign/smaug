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
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <unbound.h>

#include "smg_net_libunbound.h"
#include "smg_id.h"
#include "smg_smime_association.h"

using namespace std;

SmgNetLibunbound::SmgNetLibunbound()
  : m_pCtx(NULL)
{

}

SmgNetLibunbound::~SmgNetLibunbound()
{
  if (NULL != m_pCtx)
  {
    ub_ctx_delete(m_pCtx);
    m_pCtx = NULL;
  }
}

bool SmgNetLibunbound::init(const char *p_szRootTaFile /*= NULL*/)
{
  bool bRet = false;

  if (NULL != m_pCtx)
  {
    ub_ctx_delete(m_pCtx);
    m_pCtx = NULL;
  }

  int iErr = 0;
  if (NULL == p_szRootTaFile || '\0' == p_szRootTaFile[0])
  {
    struct stat tStat;
    memset(&tStat, 0, sizeof(tStat));
    if (0 == stat(SMG_LIBUNBOUND_TA_FILE, &tStat))
    {
      p_szRootTaFile = SMG_LIBUNBOUND_TA_FILE;
    }
    else if (0 == stat(SMG_LIBUNBOUND_LIN_TA_FILE, &tStat))
    {
      p_szRootTaFile = SMG_LIBUNBOUND_LIN_TA_FILE;
    }
    else
    {
      smg_log("Unable to find DNSSEC trust anchor file at either '%s' or '%s'\n", 
              SMG_LIBUNBOUND_TA_FILE,
              SMG_LIBUNBOUND_LIN_TA_FILE);
      p_szRootTaFile = NULL;
    }
  }

  if (NULL == p_szRootTaFile)
  {
    smg_log("Unable to find DNSSEC trust anchor file at either '%s' or '%s'\n",
            SMG_LIBUNBOUND_TA_FILE,
            SMG_LIBUNBOUND_LIN_TA_FILE);
  }
  else if (NULL == (m_pCtx = ub_ctx_create()))
  {
    smg_log("Unable to create libunbound context.\n");
  }
  /*
  else if (0 != (iErr = ub_ctx_resolvconf(m_pCtx, "/etc/resolv.conf")))
  {
    smg_log("Unable to load /etc/resolv.conf: '%s' (errno: '%s')\n", ub_strerror(iErr), strerror(errno));
  }
  */
  else if (0 != (iErr = ub_ctx_hosts(m_pCtx, "/etc/hosts")))
  {
    smg_log("Unable to load /etc/hosts: '%s' (errno: '%s')\n", ub_strerror(iErr), strerror(errno));
  }
  else if (0 != (iErr = ub_ctx_add_ta_file(m_pCtx, p_szRootTaFile)))
  {
    smg_log("Unable to load '%s': '%s'\n", p_szRootTaFile, ub_strerror(iErr));
  }
  else
  {
    bRet = true;
  }

  return bRet;
}

bool SmgNetLibunbound::init(std::string &p_sRootTaFile)
{
  return init(p_sRootTaFile.c_str());
}

bool SmgNetLibunbound::lookupSmimeID(SmgID &p_oID,
                                uint32_t &p_uTTL)
{
  bool bRet = false;

  int iErr = 0;
  struct ub_result *pResult = NULL;
  string sDomain = p_oID.getSmimeName();

  if (NULL == m_pCtx)
  {
    smg_log("Net layer not initialize.\n");
  }
  else if (0 != (iErr = ub_resolve(m_pCtx, sDomain.c_str(), SMG_SMIMEA_RR_TYPE, 1, &pResult)))
  {
    smg_log("Unable to resolve '%s': %s\n", sDomain.c_str(), ub_strerror(iErr));
  }
  else if (NULL == pResult)
  {
    smg_log("Got no error, but NULL result for domain '%s'\n", sDomain.c_str());
  }
  else if (!pResult->havedata)
  {
    smg_log("Result does not have data for '%s'\n", sDomain.c_str());
  }
  else if (!pResult->secure)
  {
    smg_log("Result for '%s' is not secure.\n", sDomain.c_str());
  }
  else
  {
smg_log("Going to loop over results...\n");
smg_log("Result has rcode %d and is bogus? %d\n", pResult->rcode, pResult->bogus);
    p_uTTL = pResult->ttl;
    for (int i = 0; pResult->data[i]; i++)
    {
smg_log("Result %d...\n", i);
      SmgSmimeAssociation oAssoc;
      if (!oAssoc.fromWire((uint8_t *) pResult->data[i], pResult->len[i]))
      {
        smg_log("Unable to parse data from wire format.\n");
      }
      else if (!p_oID.addAssociation(oAssoc))
      {
        smg_log("Unable to add association.\n");
      }
      else
      {
        bRet = true;
      }
    }
smg_log("Done looping\n");
  }

  if (NULL != pResult)
  {
smg_log("Freeing result set.\n");
    ub_resolve_free(pResult);
    pResult = NULL;
  }

  return bRet;
}
