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

#ifndef _WEBPKI_CRYPTO_H_
#define _WEBPKI_CRYPTO_H_

#include <limits.h>

#if INT_MAX == 32767
typedef unsigned long CRYPTO_U32;
#else
typedef unsigned int CRYPTO_U32;
#endif

namespace webpki
  {

	class AESProvider
      {
        public:

          AESProvider ();

          static const int AES_BLOCK_SIZE = 16;

          void setKey (const unsigned char* raw_key, int key_length, bool encrypt);

          const char* encrypt (unsigned char* out, int& in_out_len, const unsigned char* in, const unsigned char* iv, bool pad);

        private:

          void AES_cbc_ecb_encrypt (const unsigned char* in, unsigned char* out, int length, const unsigned char* iv);

          void AES_set_encrypt_key (const unsigned char* raw_key);

          void AES_set_decrypt_key (const unsigned char* raw_key);

          void AES_decrypt (const unsigned char* in, unsigned char* out);

          void AES_encrypt (const unsigned char* in, unsigned char* out);

		  static const int AES_MAXNR = 14;

          struct
            {
              CRYPTO_U32 rd_key[4 * (AES_MAXNR + 1)];
              int rounds;
              int length_in_bytes;
            } m_the_key;

          bool m_encrypt;

          const char* m_error;
      };

	class SHA256Provider
	  {
	    public:

	      SHA256Provider ();

	      static const int DIGEST_LENGTH = 32;

	      void update (const unsigned char* data, int length);

	      const char* doFinal (unsigned char* digest);

	    private:

	      void init ();

	      void hash_block_data_order (const unsigned char* data, int num);

	      static const int SHA_LBLOCK = 16;

	      static const int SHA_CBLOCK = (SHA_LBLOCK * 4);

	      struct
	        {
	          CRYPTO_U32 h[8];
	          CRYPTO_U32 Nl, Nh;
	          CRYPTO_U32 data[SHA_LBLOCK];
	          unsigned int num, md_len;
	        } m_sha256_ctx;

          const char* m_error;

          bool m_needs_init;
	  };

  }  /* namespace */

#endif /* _WEBPKI_CRYPTO_H_ */
