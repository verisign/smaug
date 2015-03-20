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

#ifndef _SMG_TBIRD_H
#define _SMG_TBIRD_H

extern "C" {
  // Legacy
  // const char * init(const char *p_szEmailAddr, const char *p_szCertFilePath);
  int init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile);
  const char *hash_sha224(const char *p_szKey);
  const char *ds_encrypt(const char *p_szEmail, const char *p_pBuf);
  const char *ds_decrypt(const char *p_szEmail, const char *p_pBuf);
  const char *ds_sign(const char *p_szEmail,   const char *p_pBuf, const char *p_szCertFile);
  const char *ds_sign2(const char *p_szEmail,   const char *p_pBuf);
  //verify returns 1 == OK, 0 == ERR per CMS_verify
  int ds_verify(const char *p_szEmail, const char *p_pBuf);

  // Current
  int smg_init(const char *p_szEmailAddr, const char *p_szCertFilePath, const char *p_szLogFile);
  // returns 1 == OK, 0 == ERR per CMS_verify
  int smg_encrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput);
  int smg_decrypt(const char *p_szEmail, const char *p_pBuf, const char **p_pOutput);
  int smg_sign(const char *p_szEmail,   const char *p_pBuf, const char **p_pOutput);
  int smg_verify(const char *p_szEmail, const char *p_pBuf);
  int smg_lookup(const char *p_szEmail, int p_iEnc);
}



#endif
