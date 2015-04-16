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
#include <string.h>

#include "smg_net.h"
#include "smg_defs.h"

using namespace std;

SmgNet::SmgNet()
{

}

SmgNet::~SmgNet()
{

}

bool SmgNet::init(const char *p_szRootTaFile /*= NULL*/)
{
  return m_oEngine.init(p_szRootTaFile);
}

bool SmgNet::init(std::string &p_sRootTaFile)
{
  return m_oEngine.init(p_sRootTaFile);
}

bool SmgNet::lookupSmimeID(SmgID &p_oID, SmgCryptAction_e p_eAction)
{
  return m_oEngine.lookupSmimeID(p_oID, p_eAction);
}

bool SmgNet::lookupSmimeID(SmgID &p_oID, SmgCryptAction_e p_eAction, uint32_t &p_uTTL)
{
  return m_oEngine.lookupSmimeID(p_oID, p_eAction, p_uTTL);
}

bool SmgNet::chaseLocator(SmgSmimeAssociation &p_oAssoc)
{
  return m_oEngine.chaseLocator(p_oAssoc);
}

