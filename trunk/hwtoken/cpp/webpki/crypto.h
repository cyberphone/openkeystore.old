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


	class SHACore
	  {
        public:

          virtual void update (const unsigned char* data, int length) = 0;

	      virtual const char* doFinal (unsigned char* digest) = 0;

	      const char* doFinal (unsigned char* digest, const unsigned char* data, int length);

        protected:

          friend class HMACCore;

	      static const int SHA_LBLOCK = 16;                // SHA1 & SHA256 share these

	      static const int SHA_CBLOCK = (SHA_LBLOCK * 4);  // SHA1 & SHA256 share these

	      const char* m_error;

          bool m_needs_init;
	  };


	class SHA1Provider : public SHACore
	  {
	    public:

	      SHA1Provider ();

		  virtual void update (const unsigned char* data, int length);

	      virtual const char* doFinal (unsigned char* digest);

	      static const int DIGEST_LENGTH = 20;

	    private:

          friend class HMAC_SHA1Provider;

	      void _init ();

	      void hash_block_data_order (const unsigned char* data, int num);

	      struct
	        {
	    	  CRYPTO_U32 h0, h1, h2, h3, h4;
	    	  CRYPTO_U32 Nl, Nh;
	    	  CRYPTO_U32 data[SHA_LBLOCK];
	    	  unsigned int num;
	        } m_sha1_ctx;
	  };


	class SHA256Provider : public SHACore
	  {
	    public:

		  SHA256Provider ();

		  virtual void update (const unsigned char* data, int length);

	      virtual const char* doFinal (unsigned char* digest);

	      static const int DIGEST_LENGTH = 32;

	    private:

          friend class HMAC_SHA256Provider;

	      void _init ();

	      void hash_block_data_order (const unsigned char* data, int num);

	      struct
	        {
	          CRYPTO_U32 h[8];
	          CRYPTO_U32 Nl, Nh;
	          CRYPTO_U32 data[SHA_LBLOCK];
	          unsigned int num;
	        } m_sha256_ctx;
	  };


	class HMACCore
	  {
	    public:

          void init (const unsigned char* key, int key_length);

          void update (const unsigned char* data, int length);

		  const char* doFinal (unsigned char* digest);

		  const char* doFinal (unsigned char* digest, const unsigned char* data, int length);

	    protected:

	      HMACCore (SHACore& outer, SHACore& inner, int digest_length);

        private:

          SHACore* m_outer_save;

          SHACore* m_inner_save;

          int m_digest_length;

          char* m_error;
	  };


	class HMAC_SHA1Provider : public HMACCore
      {
        public:

          HMAC_SHA1Provider ();

        private:

          SHA1Provider m_outer;

          SHA1Provider m_inner;
      };


	class HMAC_SHA256Provider : public HMACCore
      {
        public:

          HMAC_SHA256Provider ();

        private:

          SHA256Provider m_outer;

          SHA256Provider m_inner;
      };

  }  /* namespace */

#endif /* _WEBPKI_CRYPTO_H_ */
