package org.webpki.pkcs7.test;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.pkcs7.PKCS7Verifier;

public class Verify
  {
    public static void main (String[] args) throws Exception
      {
        if (args.length != 2 && (args.length != 3 || !args[2].equals ("-d")))
          {
            System.out.println ("Verify reffile signaturefile [-d]\n\n" +
                                "   reffile       : where raw data is read and compared\n"+
                                "   signaturefile : PKCS #7 signature\n"+
                                "   -d            : detached signature\n");
            System.exit (3);
          }
        VerifierInterface verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        PKCS7Verifier pkcs7 = new PKCS7Verifier (verifier);
        verifier.setTrustedRequired (false);
        if (args.length == 2)
          {
            byte[] read_data = pkcs7.verifyMessage (ArrayUtil.readFile (args[1]));
            if (!ArrayUtil.compare (read_data, ArrayUtil.readFile (args[0])))
              {
                throw new Exception ("Data mismatch");
              }
          }
        else
          {
            pkcs7.verifyDetachedMessage (ArrayUtil.readFile (args[0]), ArrayUtil.readFile (args[1]));
          }
        System.out.println ("\nVERIFICATION SUCCESSFUL\n\n" + verifier.getSignerCertificateInfo ().toString ());
      }
  }
