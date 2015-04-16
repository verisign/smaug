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


#ifndef _SMG_NET_GETDNS_H
#define _SMG_NET_GETDNS_H

#include <getdns/getdns.h>

#include "smg_net_engine.h"
#include "smg_defs.h"

#define SMG_GETDNS_TA_FILE "/etc/unbound/getdns-root.key"

class SmgSmimeAssociation;
class SmgID;

class SmgNetGetDNS : public SmgNetEngine
{
  // Member Variables
  private:
    bool m_bInit;
    struct getdns_context *m_pGetDNS;

  // Methods
  public:
    SmgNetGetDNS();
    virtual ~SmgNetGetDNS();

    virtual bool init(const char *p_szRootTaFile = NULL);
    virtual bool init(std::string &p_sRootTaFile);

    virtual bool lookupSmimeID(SmgID &p_oID,
                          SmgCryptAction_e p_eAction);
    virtual bool lookupSmimeID(SmgID &p_oID,
                          SmgCryptAction_e p_eAction,
                          uint32_t &p_uTTL);
};

#endif
