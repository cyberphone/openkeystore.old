package org.webpki.keygen2.test;

import java.math.BigInteger;

import java.util.Date;


import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.ECDomains;
import org.webpki.crypto.JKSSignCertStore;

import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethods;
import org.webpki.keygen2.PatternRestrictions;

public class keyinitreq_enc
  {

    private static void show ()
      {
        System.out.println ("keyinitreq_enc out_file\n");
        System.exit (3);
      }

    static KeyInitializationRequestEncoder create () throws Exception
      {
        Date server_time = DOMReaderHelper.parseDateTime (Constants.SERVER_TIME).getTime ();


        KeyInitializationRequestEncoder kre =
                           new KeyInitializationRequestEncoder (Constants.SESSION_ID,
                                                           Constants.REQUEST_ID,
                                                           "https://ca.example.com/keygenres",
                                                           server_time);
 //      kre.setAES256Mode (true);

       KeyInitializationRequestEncoder.PUKPolicy puk = kre.createPUKPolicy (new byte[]{4,6,8,9}, PassphraseFormats.NUMERIC, 3);

       KeyInitializationRequestEncoder.PINPolicy pin = kre.createPINPolicy (PassphraseFormats.NUMERIC,
                                                           5,
                                                           8,
                                                           3,
                                                           puk).
                                                           setGrouping (PINGrouping.SHARED).
                                                           setPatternRestrictions (new PatternRestrictions[]
                                                             {PatternRestrictions.THREE_IN_A_ROW,
                                                              PatternRestrictions.SEQUENCE});

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048),
                       null).setExportable (true);

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.EC (ECDomains.P_256),
                       pin);

        kre.createKey (KeyGen2KeyUsage.SYMMETRIC_KEY,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                       pin);

        kre.createKey (KeyGen2KeyUsage.SIGNATURE,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048, BigInteger.valueOf (3)),
                       pin);
                                                           
        kre.createKeyWithPresetPIN (KeyGen2KeyUsage.UNIVERSAL,
                                    new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                                    kre.createPINPolicy (PassphraseFormats.NUMERIC,
                                                                              6,
                                                                              6,
                                                                              3,
                                                                              puk).setGrouping (PINGrouping.SHARED),
                                                                              new byte[]{4,6,8,9},
                                    true,
                                    true);

        kre.createDevicePINProtectedKey (KeyGen2KeyUsage.AUTHENTICATION,
                                         new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048));

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                        new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                        null);

//        kre.setOutputEncryptionCertificate (true);
                                                          
        JKSSignCertStore signer3 = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer3.setKey (null, DemoKeyStore.getSignerPassword ());
        kre.signRequest (signer3);


        kre.writeXML();
        return kre;
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        ArrayUtil.writeFile (args[0], create ().writeXML());
      }
  }
