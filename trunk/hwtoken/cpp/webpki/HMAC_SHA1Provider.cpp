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

HMAC_SHA1Provider::HMAC_SHA1Provider () : HMACCore (m_outer, m_inner, SHA1Provider::DIGEST_LENGTH)
  {
  }

}
