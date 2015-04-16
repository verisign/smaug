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


#ifndef _SMG_ID_CACHE_H
#define _SMG_ID_CACHE_H

#include <string>

#include "smg_defs.h"

class SmgIdCache
{
  // Member Variables
  private:
    static SmgIdCache s_oInstance;

    SmgIdMap_t m_oEncMap;
    SmgIdMap_t m_oSignMap;

  // Methods
  public:
    SmgIdCache();
    virtual ~SmgIdCache();

    static SmgIdCache &getInstance();

    bool addID(SmgID &p_oID, SmgCryptAction_e p_eAction, time_t p_tTTL);
    bool lookupSmimeID(std::string &p_sID, SmgCryptAction_e p_eAction, SmgID &p_oOutputID);

    bool clear();
};

#endif
