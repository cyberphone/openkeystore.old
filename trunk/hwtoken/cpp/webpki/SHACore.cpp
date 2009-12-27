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

const char* SHACore::doFinal (unsigned char* digest, const unsigned char* data, int length)
  {
    update (data, length);
    return doFinal (digest);
  }

}
