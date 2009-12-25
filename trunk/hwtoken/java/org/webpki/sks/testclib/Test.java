package org.webpki.sks.testclib;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test
  {
    int passes;
    
    private Test (int passes)
      {
        this.passes = passes;
      }

    private void singleAES (byte[] raw_key, byte[] iv, byte[] msg, boolean pad) throws Exception
      {
        AESProvider aes = new AESProvider ();
        aes.setKey (raw_key, true);
        byte[] enc = aes.encrypt (msg, iv, pad);
        aes.setKey (raw_key, false);
        byte[] res = aes.encrypt (enc, iv, pad);

        String mode = (iv == null ? "AES/ECB/" : "AES/CBC/") +
        (pad ? "PKCS5Padding" : "NoPadding");
        
        Cipher crypt = Cipher.getInstance (mode);
        if (iv == null)
          {
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (raw_key, "AES"));
          }
        else
          {
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (raw_key, "AES"), new IvParameterSpec (iv));
          }
        byte[] jenc = crypt.doFinal (msg);

        if (!ArrayUtil.compare (res, msg) || !ArrayUtil.compare (enc, jenc))
          {
            System.out.println ("Failed AES msg.length=" + msg.length + " mode=" + mode);
            System.out.println ("In=\n" + DebugFormatter.getHexDebugData (msg) +
                                "\njEnc=\n" + DebugFormatter.getHexDebugData (jenc) +
                                "\nEnc=\n" + DebugFormatter.getHexDebugData (enc) +
                                "\nIV=\n" + DebugFormatter.getHexDebugData (iv) +
                                "\nOut=\n" + DebugFormatter.getHexDebugData (res));
            System.exit (-3);
          }
        aes.dispose ();
      }
    

    private void testAES () throws Exception
      {
        System.out.println ("AES Testing Begins");
        for (int i = 0; i < passes; i++)
          {
            int key_len = (i & 1) * 16 + 16;
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes (iv);
            byte[] raw_key = new byte[key_len];
            random.nextBytes (raw_key);
            byte[] msg_3 = new byte[3];
            random.nextBytes (msg_3);
            byte[] msg_16 = new byte[16];
            random.nextBytes (msg_16);
            byte[] msg_32 = new byte[32];
            random.nextBytes (msg_32);
            byte[] msg_35 = new byte[35];
            random.nextBytes (msg_35);
            byte[] msg_300 = new byte[300];
            random.nextBytes (msg_300);

            singleAES (raw_key, iv, msg_3, true);
            singleAES (raw_key, iv, msg_16, true);
            singleAES (raw_key, iv, msg_32, true);
            singleAES (raw_key, iv, msg_35, true);
            singleAES (raw_key, iv, msg_300, true);

// Illegal            singleAES (raw_key, iv, msg_3, false);
            singleAES (raw_key, iv, msg_16, false);
            singleAES (raw_key, iv, msg_32, false);

            singleAES (raw_key, null, msg_3, true);
            singleAES (raw_key, null, msg_16, true);
            singleAES (raw_key, null, msg_32, true);
            singleAES (raw_key, null, msg_35, true);
            singleAES (raw_key, null, msg_300, true);

// Illegal            singleAES (raw_key, iv, msg_3, false);
            singleAES (raw_key, null, msg_16, false);
            singleAES (raw_key, null, msg_32, false);
          }
        System.out.println ("AES Testing Passed!");
      }

    public static void main (String[] argc) throws Exception
      {
        new Test (1000).testAES ();
      }
  }
