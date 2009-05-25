package org.webpki.pkcs7.test;

import org.webpki.crypto.JKSSignCertStore;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.pkcs7.PKCS7Signer;

public class Sign
  {
    public static void main (String[] args) throws Exception
      {
        if (args.length != 2 && (args.length != 3 || !args[2].equals ("-d")))
          {
            System.out.println ("Sign outputfile inputfile [-d]\n\n" +
                                "   outputfile: where signed data is written\n"+
                                "   inputfile : where data to be signed is read\n"+
                                "   -d        : detached signature\n");
            System.exit (3);
          }
        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getMarionKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        PKCS7Signer pkcs7 = new PKCS7Signer (signer);
//        pkcs7.setSignatureAlgorithm (org.webpki.crypto.SignatureAlgorithms.RSA_SHA256);
        pkcs7.setExtendedCertPath (true);
        ArrayUtil.writeFile (args[0], 
                                args.length == 2 ? 
                                    pkcs7.signMessage (ArrayUtil.readFile (args[1]))
                                                 :
                                    pkcs7.signDetachedMessage (ArrayUtil.readFile (args[1])));
        System.out.println ("\nSIGNING SUCCESSFUL\n\n" + signer.getSignerCertificateInfo ().toString ());
      }
  }
