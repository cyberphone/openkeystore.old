#include <stdio.h>

static void hex (int i)
  {
    if (i < 10)
      {
        putchar (i + 48);
      }
    else
      {
        putchar (i + 55);
      }
  }

static void twohex (int i)
  {
    i &= 0xFF;
    hex (i / 16);
    hex (i % 16);
  }

static  void addrhex (int i)
  {
    if (i > 65535)
      {
        twohex (i / 65536);
        i %= 65536;
      }
    twohex (i / 256);
    twohex (i % 256);
  }

#include "hexdump.h"

namespace webpki
{

void HexDump::printDebugData (const unsigned char *indata, const int length, int bytes_per_line)
  {
    int index = 0;
    int i = 0;
    if (length == 0)
      {
        printf ("No data");
        return;
      }
    bool only_data = false;
    if (bytes_per_line < 0)
      {
        bytes_per_line = -bytes_per_line;
        only_data = true;
      }
    while (index < length)
      {
        if (index > 0)
          {
            putchar ('\n');
          }
        addrhex (index);
        putchar (':');
        int q = length - index;
        if (q > bytes_per_line)
          {
            q = bytes_per_line;
          }
        for(i = 0; i < q; i++)
          {
            putchar (' ');
            twohex (indata[index + i]);
          }
        if (only_data)
          {
            index += q;
            continue;
          }
        while (i++ <= bytes_per_line)
          {
            putchar (' ');
            putchar (' ');
            putchar (' ');
          }
        putchar ('\'');
        for(i = 0; i < q; i++)
          {
            int c = indata[index++];
            if (c < 32 || c >= 127)
              {
                putchar ('.');
              }
            else
              {
                putchar (c);
              }
          }
        putchar ('\'');
        while (i++ < bytes_per_line)
          {
            putchar (' ');
          }
      }
  }


void HexDump::printHexString (const unsigned char *indata, int length)
  {
    int i = 0;
    while (i < length)
      {
        twohex (indata[i++]);
      }
  }

}


