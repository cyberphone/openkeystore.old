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
	m_sha_ctx.h[0] = INIT_DATA_h0;
	m_sha_ctx.h[1] = INIT_DATA_h1;
	m_sha_ctx.h[2] = INIT_DATA_h2;
	m_sha_ctx.h[3] = INIT_DATA_h3;
	m_sha_ctx.h[4] = INIT_DATA_h4;
	m_sha_ctx.Nl = 0;
	m_sha_ctx.Nh = 0;
	m_sha_ctx.num = 0;
	m_sha_ctx.digest_length = DIGEST_LENGTH;
  }


void SHA1Provider::hash_block_data_order (const unsigned char* data, int num)
  {
	CRYPTO_U32 A, B, C, D, E, T, l;
	int i;
	CRYPTO_U32 X[16];

	A = m_sha_ctx.h[0];
	B = m_sha_ctx.h[1];
	C = m_sha_ctx.h[2];
	D = m_sha_ctx.h[3];
	E = m_sha_ctx.h[4];

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

		m_sha_ctx.h[0] = (m_sha_ctx.h[0] + A) & 0xffffffffL;
		m_sha_ctx.h[1] = (m_sha_ctx.h[1] + B) & 0xffffffffL;
		m_sha_ctx.h[2] = (m_sha_ctx.h[2] + C) & 0xffffffffL;
		m_sha_ctx.h[3] = (m_sha_ctx.h[3] + D) & 0xffffffffL;
		m_sha_ctx.h[4] = (m_sha_ctx.h[4] + E) & 0xffffffffL;

		if (--num == 0) break;

		A = m_sha_ctx.h[0];
		B = m_sha_ctx.h[1];
		C = m_sha_ctx.h[2];
		D = m_sha_ctx.h[3];
		E = m_sha_ctx.h[4];

      }
  }


}
