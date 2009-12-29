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


namespace webpki
{

HMACCore::HMACCore (SHACore& outer, SHACore& inner)
  {
	m_outer_save = &outer;
	m_inner_save = &inner;
	m_error = NULL;
  }


void HMACCore::init (const unsigned char* key, int key_length)
  {
	unsigned char padded_key[SHACore::SHA_CBLOCK];
	if (key_length > SHACore::SHA_CBLOCK)
	  {
		m_inner_save->doFinal (padded_key, key, key_length);
		key_length = m_inner_save->m_sha_ctx.digest_length;
	  }
	else
	  {
		memcpy (padded_key, key, key_length);
	  }
	for (int i = 0; i < SHACore::SHA_CBLOCK; i++)
	  {
		padded_key[i] = i < key_length ? padded_key[i] ^ 0x36 : 0x36;
	  }
	m_inner_save->update (padded_key, SHACore::SHA_CBLOCK);
	for (int i = 0; i < SHACore::SHA_CBLOCK; i++)
	  {
		padded_key[i] = i < key_length ? padded_key[i] ^ (0x36 ^ 0x5c) : 0x5c;
	  }
	m_outer_save->update (padded_key, SHACore::SHA_CBLOCK);
  }


void HMACCore::update (const unsigned char* data, int length)
  {
	m_inner_save->update (data, length);
  }


const char* HMACCore::doFinal (unsigned char* digest)
  {
	unsigned char inner_digest[SHA256Provider::DIGEST_LENGTH];
	m_inner_save->doFinal (inner_digest);
	return m_outer_save->doFinal (digest, inner_digest, m_inner_save->m_sha_ctx.digest_length);
  }


const char* HMACCore::doFinal (unsigned char* digest, const unsigned char* data, int length)
  {
	update (data, length);
	return doFinal (digest);
  }

}
