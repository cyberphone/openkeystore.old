
#include <stdio.h>
#include <string.h>

#include "webpki/crypto.h"
#include "webpki/hexdump.h"

using namespace webpki;

#define BIG_TEST_SIZE 240

HexDump dumper;

static void dumpdata (const char *title, const unsigned char *data, int length)
  {
    printf("\n%s\n",title);
    dumper.printDebugData (data, length);
    printf("\n");
  }

int main ()
  {
    const int KEYSIZE = AESProvider::AES_BLOCK_SIZE * 2;
    const unsigned char raw_key[KEYSIZE] = {'b', 'y', '9', '8', '4', 'g', '2', 'y', 'c', '2', 'g', '7', '6', '|', 'x', 's'};
    unsigned char plaintext[BIG_TEST_SIZE];
    unsigned char ciphertext[BIG_TEST_SIZE];
    unsigned char checktext[BIG_TEST_SIZE];
    unsigned char iv[AESProvider::AES_BLOCK_SIZE] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'};
    AESProvider myaes;

    strcpy((char*)plaintext,"The quick brown fox jumped over the lazy bear");
    int in_out_len = strlen((char*)plaintext);

    // Straight encrypt

    myaes.setKey (raw_key, KEYSIZE, true);
    dumpdata ("Plaintext", plaintext, in_out_len);

    myaes.encrypt (ciphertext, in_out_len, plaintext, iv, true);
    dumpdata ("Ciphertext", (unsigned char*)ciphertext, in_out_len);

    // Straight decrypt

    myaes.setKey (raw_key, KEYSIZE, false);
    myaes.encrypt (checktext, in_out_len, ciphertext, iv, true);
    dumpdata ("Restored Plaintext", checktext, in_out_len);
  }
