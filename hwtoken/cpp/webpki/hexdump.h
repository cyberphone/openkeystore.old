/*
 * hexdump.h
 *
 *  Created on: Dec 15, 2009
 *      Author: Anders
 */

#ifndef _WEBPKI_HEXDUMP_H_
#define _WEBPKI_HEXDUMP_H_

namespace webpki
  {
    class HexDump
      {
        public:

          void printDebugData (const unsigned char *indata, const int length, const int bytes_per_line = 16);

          void printHexString (const unsigned char *indata, int length);
      };
   }

#endif /* _WEBPKI_HEXDUMP_H_ */
