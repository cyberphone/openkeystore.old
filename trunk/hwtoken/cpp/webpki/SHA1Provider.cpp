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

#define INIT_DATA_h0 0x67452301UL
#define INIT_DATA_h1 0xefcdab89UL
#define INIT_DATA_h2 0x98badcfeUL
#define INIT_DATA_h3 0x10325476UL
#define INIT_DATA_h4 0xc3d2e1f0UL

#define HASH_MAKE_STRING(s)   do {	\
	unsigned long ll;		\
	ll=m_sha1_ctx.h0; HOST_l2c(ll,(s));	\
	ll=m_sha1_ctx.h1; HOST_l2c(ll,(s));	\
	ll=m_sha1_ctx.h2; HOST_l2c(ll,(s));	\
	ll=m_sha1_ctx.h3; HOST_l2c(ll,(s));	\
	ll=m_sha1_ctx.h4; HOST_l2c(ll,(s));	\
	} while (0)

#define Xupdate(a,ix,ia,ib,ic,id)	( (a)=(ia^ib^ic^id),	\
					  ix=(a)=ROTATE((a),1)	\
					)

#define K_00_19	0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

/* As  pointed out by Wei Dai <weidai@eskimo.com>, F() below can be
 * simplified to the code in F_00_19.  Wei attributes these optimisations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 * #define F(x,y,z) (((x) & (y))  |  ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#define	F_00_19(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	F_20_39(b,c,d)	((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)	(((b) & (c)) | (((b)|(c)) & (d)))
#define	F_60_79(b,c,d)	F_20_39(b,c,d)

#define BODY_00_15(xi)		 do {	\
	T=E+K_00_19+F_00_19(B,C,D);	\
	E=D, D=C, C=ROTATE(B,30), B=A;	\
	A=ROTATE(A,5)+T+xi;	    } while(0)

#define BODY_16_19(xa,xb,xc,xd)	 do {	\
	Xupdate(T,xa,xa,xb,xc,xd);	\
	T+=E+K_00_19+F_00_19(B,C,D);	\
	E=D, D=C, C=ROTATE(B,30), B=A;	\
	A=ROTATE(A,5)+T;	    } while(0)

#define BODY_20_39(xa,xb,xc,xd)	 do {	\
	Xupdate(T,xa,xa,xb,xc,xd);	\
	T+=E+K_20_39+F_20_39(B,C,D);	\
	E=D, D=C, C=ROTATE(B,30), B=A;	\
	A=ROTATE(A,5)+T;	    } while(0)

#define BODY_40_59(xa,xb,xc,xd)	 do {	\
	Xupdate(T,xa,xa,xb,xc,xd);	\
	T+=E+K_40_59+F_40_59(B,C,D);	\
	E=D, D=C, C=ROTATE(B,30), B=A;	\
	A=ROTATE(A,5)+T;	    } while(0)

#define BODY_60_79(xa,xb,xc,xd)	 do {	\
	Xupdate(T,xa,xa,xb,xc,xd);	\
	T=E+K_60_79+F_60_79(B,C,D);	\
	E=D, D=C, C=ROTATE(B,30), B=A;	\
	A=ROTATE(A,5)+T+xa;	    } while(0)

namespace webpki
{

const int SHA1Provider::DIGEST_LENGTH;


SHA1Provider::SHA1Provider ()
  {
	_init ();
  }


void SHA1Provider::_init ()
  {
    m_error = NULL;
	m_needs_init = false;
	m_sha1_ctx.h0 = INIT_DATA_h0;
	m_sha1_ctx.h1 = INIT_DATA_h1;
	m_sha1_ctx.h2 = INIT_DATA_h2;
	m_sha1_ctx.h3 = INIT_DATA_h3;
	m_sha1_ctx.h4 = INIT_DATA_h4;
	m_sha1_ctx.Nl = 0;
	m_sha1_ctx.Nh = 0;
	m_sha1_ctx.num = 0;
  }


void SHA1Provider::hash_block_data_order (const unsigned char* data, int num)
  {
	CRYPTO_U32 A, B, C, D, E, T, l;
	int i;
	CRYPTO_U32 X[16];

	A = m_sha1_ctx.h0;
	B = m_sha1_ctx.h1;
	C = m_sha1_ctx.h2;
	D = m_sha1_ctx.h3;
	E = m_sha1_ctx.h4;

	while (true)
	  {
	    for (i = 0; i < 16; i++)
	      {
	    	HOST_c2l(data,l); X[i]=l; BODY_00_15(X[i]);
	      }
	    for (i = 0; i < 4; i++)
	      {
	    	BODY_16_19(X[i], X[i+2], X[i+8], X[(i+13)&15]);
	      }
	    for (;i < 24; i++)
	      {
	    	BODY_20_39(X[i&15], X[(i+2)&15], X[(i+8)&15], X[(i+13)&15]);
	      }
	    for (i = 0; i < 20; i++)
	      {
	    	BODY_40_59(X[(i+8)&15], X[(i+10)&15], X[i&15], X[(i+5)&15]);
	      }
	    for (i = 4; i < 24; i++)
	      {
	    	BODY_60_79(X[(i+8)&15], X[(i+10)&15], X[i&15], X[(i+5)&15]);
	      }

		m_sha1_ctx.h0 = (m_sha1_ctx.h0 + A) & 0xffffffffL;
		m_sha1_ctx.h1 = (m_sha1_ctx.h1 + B) & 0xffffffffL;
		m_sha1_ctx.h2 = (m_sha1_ctx.h2 + C) & 0xffffffffL;
		m_sha1_ctx.h3 = (m_sha1_ctx.h3 + D) & 0xffffffffL;
		m_sha1_ctx.h4 = (m_sha1_ctx.h4 + E) & 0xffffffffL;

		if (--num == 0) break;

		A = m_sha1_ctx.h0;
		B = m_sha1_ctx.h1;
		C = m_sha1_ctx.h2;
		D = m_sha1_ctx.h3;
		E = m_sha1_ctx.h4;

      }
  }


void SHA1Provider::update (const unsigned char* data, int data_length)
  {
    unsigned char *p;
    CRYPTO_U32 l;
    int n;

    if (m_needs_init)
      {
        _init ();
      }

    if (data_length == 0) return;

    l = (m_sha1_ctx.Nl + (((CRYPTO_U32)data_length)<<3))&0xffffffffUL;
    /* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
     * Wei Dai <weidai@eskimo.com> for pointing it out. */
    if (l < m_sha1_ctx.Nl) /* overflow */
      {
        m_sha1_ctx.Nh++;
      }
    m_sha1_ctx.Nh += (data_length >> 29);   /* might cause compiler warning on 16-bit */
    m_sha1_ctx.Nl = l;

    n = m_sha1_ctx.num;
    if (n != 0)
      {
        p = (unsigned char*) m_sha1_ctx.data;

        if (data_length >= SHA_CBLOCK || data_length + n >= SHA_CBLOCK)
          {
            memcpy (p + n, data, SHA_CBLOCK - n);
            hash_block_data_order (p, 1);
            n      = SHA_CBLOCK-n;
            data  += n;
            data_length   -= n;
            m_sha1_ctx.num = 0;
            memset (p, 0, SHA_CBLOCK);   /* keep it zeroed */
          }
        else
          {
            memcpy (p+n, data, data_length);
            m_sha1_ctx.num += (unsigned int)data_length;
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

    if (data_length != 0)
      {
        p = (unsigned char *)m_sha1_ctx.data;
        m_sha1_ctx.num = data_length;
        memcpy (p, data, data_length);
      }
  }


const char* SHA1Provider::doFinal (unsigned char* out)
  {
    m_needs_init = true;
    if (m_error)
      {
        return m_error;
      }
    unsigned char *p = (unsigned char *)m_sha1_ctx.data;
    int n = m_sha1_ctx.num;

    p[n] = 0x80; /* there is always room for one */
    n++;

    if (n > (SHA_CBLOCK-8))
      {
        memset (p+n, 0, SHA_CBLOCK - n);
        n = 0;
        hash_block_data_order (p,1);
      }
    memset (p+n, 0, SHA_CBLOCK - 8 - n);

    p += SHA_CBLOCK - 8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
    (void)HOST_l2c(m_sha1_ctx.Nh, p);
    (void)HOST_l2c(m_sha1_ctx.Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
    (void)HOST_l2c(m_sha1_ctx.Nl, p);
    (void)HOST_l2c(m_sha1_ctx.Nh, p);
#endif
    p -= SHA_CBLOCK;
    hash_block_data_order (p,1);
    m_sha1_ctx.num = 0;
    memset (p, 0,SHA_CBLOCK);

#ifndef HASH_MAKE_STRING
#error "HASH_MAKE_STRING must be defined!"
#else
    HASH_MAKE_STRING(out);
#endif
    return m_error;
  }

}
