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


#ifndef _SMG_ID_H
#define _SMG_ID_H

#include <string>

#include "smg_defs.h"

class SmgSmimeAssociation;

class SmgID
{
  // Member Variables
  private:
    std::string m_sEmailAddr;
    std::string m_sUser;
    std::string m_sUserHash;
    std::string m_sDomain;
    std::string m_sSmimeName;
    SmgSmimeAssocList_t m_oAssocs;

  // Methods
  public:
    SmgID();
    SmgID(const SmgID &p_oRHS);
    virtual ~SmgID();

    bool init(std::string &p_sEmailAddr);

    std::string &getEmail();
    std::string &getDomain();
    std::string &getSmimeName();
    std::string &getInbox();

    bool addAssociation(SmgSmimeAssociation &p_oAssoc);

    SmgSmimeAssocKIter_t beginAssociations() const;
    SmgSmimeAssocKIter_t endAssociations() const;
    size_t numAssociations() const;

    virtual SmgID &operator=(const SmgID &p_oRHS);

  protected:
    bool clear();

};

#endif
