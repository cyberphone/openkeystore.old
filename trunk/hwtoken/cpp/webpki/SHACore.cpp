/* ====================================================================
 * Copyright (c) 1998-2010 The OpenSSL Project.  All rights reserved.
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 * ====================================================================
 * C++ adoption was made by Anders Rundgren (anders.rundgren@telia.com)
 * ====================================================================
 */

#include <string.h>
#include <stdlib.h>

#include "crypto.h"

#include "_shacommon.h"

namespace webpki
{

const int SHACore::SHA_LBLOCK;

const int SHACore::SHA_CBLOCK;


const char* SHACore::doFinal (unsigned char* digest, const unsigned char* data, int length)
  {
    update (data, length);
    return doFinal (digest);
  }


void SHACore::update (const unsigned char* data, int data_length)
  {
    unsigned char *p;
    CRYPTO_U32 l;
    int n;

    if (m_needs_init)
      {
        _init ();
      }

    if (data_length == 0) return;

    l = (m_sha_ctx.Nl + (((CRYPTO_U32)data_length)<<3))&0xffffffffUL;
    /* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
     * Wei Dai <weidai@eskimo.com> for pointing it out. */
    if (l < m_sha_ctx.Nl) /* overflow */
      {
        m_sha_ctx.Nh++;
      }
    m_sha_ctx.Nh += (data_length >> 29);   /* might cause compiler warning on 16-bit */
    m_sha_ctx.Nl = l;

    n = m_sha_ctx.num;
    if (n != 0)
      {
        p = (unsigned char*) m_sha_ctx.data;

        if (data_length >= SHA_CBLOCK || data_length + n >= SHA_CBLOCK)
          {
            memcpy (p + n, data, SHA_CBLOCK - n);
            hash_block_data_order (p, 1);
            n = SHA_CBLOCK - n;
            data += n;
            data_length -= n;
            m_sha_ctx.num = 0;
            memset (p, 0, SHA_CBLOCK);   /* keep it zeroed */
          }
        else
          {
            memcpy (p+n, data, data_length);
            m_sha_ctx.num += (unsigned int)data_length;
            return;
          }
      }

    n = data_length / SHA_CBLOCK;
    if (n > 0)
      {
        hash_block_data_order (data, n);
        n    *= SHA_CBLOCK;
        data += n;
        data_length  -= n;
      }

    if (data_length)
      {
        p = (unsigned char *)m_sha_ctx.data;
        m_sha_ctx.num = data_length;
        memcpy (p, data, data_length);
      }
  }


const char* SHACore::doFinal (unsigned char* out)
  {
    m_needs_init = true;
    if (m_error)
      {
        return m_error;
      }
    unsigned char *p = (unsigned char *)m_sha_ctx.data;
    int n = m_sha_ctx.num;

    p[n] = 0x80; /* there is always room for one */
    n++;

    if (n > (SHA_CBLOCK - 8))
      {
        memset (p+n, 0, SHA_CBLOCK - n);
        n = 0;
        hash_block_data_order (p,1);
      }
    memset (p+n, 0, SHA_CBLOCK - 8 - n);

    p += SHA_CBLOCK - 8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
    (void)HOST_l2c(m_sha_ctx.Nh, p);
    (void)HOST_l2c(m_sha_ctx.Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void)HOST_l2c(m_sha_ctx.Nl, p);
    (void)HOST_l2c(m_sha_ctx.Nh, p);
#endif
    p -= SHA_CBLOCK;
    hash_block_data_order (p,1);
    m_sha_ctx.num = 0;
    memset (p, 0, SHA_CBLOCK);

    for (int xn = 0; xn < m_sha_ctx.digest_length/4; xn++)
      {
    	CRYPTO_U32 ll = m_sha_ctx.h[xn]; HOST_l2c(ll,(out));
      }
    return m_error;
  }


}
