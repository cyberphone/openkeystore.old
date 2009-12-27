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

#include "crypto.h"

namespace webpki
{

HMAC_SHA256Provider::HMAC_SHA256Provider () : HMACCore (m_outer, m_inner, SHA256Provider::DIGEST_LENGTH, SHA256Provider::SHA_CBLOCK)
  {
  }

}
