
#include <stdio.h>
#include <string.h>

#include "webpki/crypto.h"
#include "webpki/hexdump.h"

using namespace webpki;

unsigned char app_b1[SHA256Provider::DIGEST_LENGTH] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
    0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
    0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };

unsigned char app_b2[SHA256Provider::DIGEST_LENGTH] = {
    0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
    0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
    0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
    0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1 };

unsigned char app_b3[SHA256Provider::DIGEST_LENGTH] = {
    0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,
    0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
    0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,
    0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0 };

#define BIG_TEST_SIZE 240

unsigned char init_hex_data[500];
int init_hex_len;

HexDump dumper;

int hex2 (int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a')
		return c - 'a' + 10;
	return c - 'A' + 10;
}

void init (const char *hex)
{
	init_hex_len = 0;
	while (*hex)
	{
		int i = hex2 (*hex++) << 4;
		init_hex_data[init_hex_len++] = (unsigned char) i + hex2 (*hex++);
	}
}

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

    SHA256Provider sha256;
    unsigned char md[SHA256Provider::DIGEST_LENGTH];

    sha256.update ((unsigned char*) "abc", 3);
    sha256.doFinal (md);

//    EVP_Digest ("abc",3,md,NULL,EVP_sha256(),NULL);
    if (memcmp(md,app_b1,sizeof(app_b1)))
    {
    printf("\nTEST 1 of 3 failed.\n");
    return 1;
    }
    else
    printf(".");

    sha256.update ((unsigned char*) "abcdbcde""cdefdefg""efghfghi""ghijhijk"
        "ijkljklm""klmnlmno""mnopnopq",56);
    sha256.doFinal (md);
    if (memcmp(md,app_b2,sizeof(app_b2)))
    {
    printf("\nTEST 2 of 3 failed.\n");
    return 1;
    }
    else
    printf(".");

    for (int i=0;i<1000000;i+=160)
      sha256.update ((unsigned char*) "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa"
                "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa"
                "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa"
                "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa"
                "aaaaaaaa""aaaaaaaa""aaaaaaaa""aaaaaaaa",
                (1000000-i)<160?1000000-i:160);
    sha256.doFinal (md);
    if (memcmp(md,app_b3,sizeof(app_b3)))
    {
    printf("\nTEST 3 of 3 failed.\n");
    return 1;
    }
    else
    printf(".");
    printf(" SHA passed.\n");

    HMAC_SHA256Provider hmac256;
    init ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "aaaaaa");
    hmac256.init (init_hex_data, init_hex_len);
    init ("54657374205573696e67204c61726765"
          "72205468616e20426c6f636b2d53697a"
          "65204b6579202d2048617368204b6579"
          "204669727374");
    hmac256.update (init_hex_data, init_hex_len);
    init ("60e431591ee0b67f0d8a26aacbf5b77f"
          "8e0bc6213728c5140546040f0ee37f54");
    hmac256.doFinal (md);
    if (memcmp(md,init_hex_data,sizeof (md)))
    {
    printf("\nHMAC TEST 1 failed.\n");
    return 1;
    }
    else
    printf(".");
    init ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaa");
    hmac256.init (init_hex_data, init_hex_len);
    init ("dddddddddddddddddddddddddddddddd"
          "dddddddddddddddddddddddddddddddd"
          "dddddddddddddddddddddddddddddddd"
          "dddd");
    hmac256.update (init_hex_data, init_hex_len);
    init ("773ea91e36800e46854db8ebd09181a7"
          "2959098b3ef8c122d9635514ced565fe");
    hmac256.doFinal (md);
    if (memcmp(md,init_hex_data,sizeof (md)))
    {
    printf("\nHMAC TEST 2 failed.\n");
    return 1;
    }
    else
    printf(".");
    init ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
           "aaaaaaaa");
    hmac256.init (init_hex_data, init_hex_len);
    init ("dddddddddddddddddddddddddddddddd"
          "dddddddddddddddddd");
    hmac256.update (init_hex_data, init_hex_len);
    init ("dddddddddddddddddddddddddddddddd"
          "dddddddddddddddddd");
    hmac256.update (init_hex_data, init_hex_len);
    init ("773ea91e36800e46854db8ebd09181a7"
          "2959098b3ef8c122d9635514ced565fe");
    hmac256.doFinal (md);
    if (memcmp(md,init_hex_data,sizeof (md)))
    {
    printf("\nHMAC TEST 3 failed.\n");
    return 1;
    }
    else
    printf(". HMAC passed.\n");

  }
