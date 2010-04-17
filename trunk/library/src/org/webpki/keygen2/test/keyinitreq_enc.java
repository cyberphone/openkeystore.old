package org.webpki.keygen2.test;

import java.math.BigInteger;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.ECDomains;
import org.webpki.crypto.JKSSignCertStore;

import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.IssuerCredentialStore;
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
        IssuerCredentialStore ics = new  IssuerCredentialStore (Constants.SESSION_ID,
                                                                Constants.REQUEST_ID);

        IssuerCredentialStore.PUKPolicy puk = ics.createPUKPolicy (new byte[]{4,6,8,9}, PassphraseFormats.NUMERIC, 3);

        IssuerCredentialStore.PINPolicy pin = ics.createPINPolicy (PassphraseFormats.NUMERIC,
                                                           5,
                                                           8,
                                                           3,
                                                           puk).
                                                           setGrouping (PINGrouping.SHARED).
                                                           setPatternRestrictions (new PatternRestrictions[]
                                                             {PatternRestrictions.THREE_IN_A_ROW,
                                                              PatternRestrictions.SEQUENCE});

        ics.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new IssuerCredentialStore.KeyAlgorithmData.RSA (2048),
                       null).setExportable (true);

        ics.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new IssuerCredentialStore.KeyAlgorithmData.EC (ECDomains.P_256),
                       pin);

        ics.createKey (KeyGen2KeyUsage.SYMMETRIC_KEY,
                       new IssuerCredentialStore.KeyAlgorithmData.RSA (1024),
                       pin);

        ics.createKey (KeyGen2KeyUsage.SIGNATURE,
                       new IssuerCredentialStore.KeyAlgorithmData.RSA (2048, BigInteger.valueOf (3)),
                       pin);
                                                           
        ics.createKeyWithPresetPIN (KeyGen2KeyUsage.UNIVERSAL,
                                    new IssuerCredentialStore.KeyAlgorithmData.RSA (1024),
                                    ics.createPINPolicy (PassphraseFormats.NUMERIC,
                                                         6,
                                                         6,
                                                         3,
                                                         puk).setGrouping (PINGrouping.SHARED),
                                    new byte[]{4,6,8,9},
                                    true);

        ics.createDevicePINProtectedKey (KeyGen2KeyUsage.AUTHENTICATION,
                                         new IssuerCredentialStore.KeyAlgorithmData.RSA (2048));

        ics.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                        new IssuerCredentialStore.KeyAlgorithmData.RSA (1024),
                        null);

        KeyInitializationRequestEncoder kre =
          new KeyInitializationRequestEncoder ("https://ca.example.com/keygenres",
                                          ics);
                                                          
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
