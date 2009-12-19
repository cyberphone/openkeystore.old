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

#define AES_MAXNR 14

#define AES_BLOCK_SIZE 16

namespace webpki
  {
    class AESProvider
      {
        public:

          AESProvider ();

          void setKey (const unsigned char *raw_key, int key_length, bool encrypt);

          const char *encrypt (unsigned char *out, int& in_out_len, const unsigned char *in, const unsigned char *iv, bool pad);

        private:

          void AES_cbc_ecb_encrypt (const unsigned char *in, unsigned char *out, const unsigned long length, const unsigned char *iv);

          void AES_set_encrypt_key (const unsigned char *raw_key);

          void AES_set_decrypt_key (const unsigned char *raw_key);

          void AES_decrypt (const unsigned char *in, unsigned char *out);

          void AES_encrypt (const unsigned char *in, unsigned char *out);

          struct
            {
          #if INT_MAX == 32767
              unsigned long rd_key[4 *(AES_MAXNR + 1)];
          #else
              unsigned int rd_key[4 *(AES_MAXNR + 1)];
          #endif
              int rounds;
              int length_in_bytes;
            } m_the_key;

          bool m_encrypt;

          const char *m_error;
      };
  }

#endif /* _WEBPKI_CRYPTO_H_ */
