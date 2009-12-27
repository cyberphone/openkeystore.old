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

#define MAX_BLOCK_SIZE 64 // SHA256 in this library

namespace webpki
{

HMACCore::HMACCore (SHACore& outer, SHACore& inner, int digest_length, int block_size)
  {
	m_outer_save = &outer;
	m_inner_save = &inner;
	m_digest_length = digest_length;
	m_block_size = block_size;
	m_error = NULL;
  }


void HMACCore::init (const unsigned char* key, int key_length)
  {
	unsigned char padded_key[MAX_BLOCK_SIZE];
	if (key_length > m_block_size)
	  {
		m_inner_save->doFinal (padded_key, key, key_length);
		key_length = m_digest_length;
	  }
	else
	  {
		memcpy (padded_key, key, key_length);
	  }
	for (int i = 0; i < m_block_size; i++)
	  {
		padded_key[i] = i < key_length ? padded_key[i] ^ 0x36 : 0x36;
	  }
	m_inner_save->update (padded_key, m_block_size);
	for (int i = 0; i < m_block_size; i++)
	  {
		padded_key[i] = i < key_length ? padded_key[i] ^ (0x36 ^ 0x5c) : 0x5c;
	  }
	m_outer_save->update (padded_key, m_block_size);
  }


void HMACCore::update (const unsigned char* data, int length)
  {
	m_inner_save->update (data, length);
  }


const char* HMACCore::doFinal (unsigned char* digest)
  {
	unsigned char inner_digest[MAX_BLOCK_SIZE];
	m_inner_save->doFinal (inner_digest);
	return m_outer_save->doFinal (digest, inner_digest, m_digest_length);
  }


const char* HMACCore::doFinal (unsigned char* digest, const unsigned char* data, int length)
  {
	update (data, length);
	return doFinal (digest);
  }

}
