package org.webpki.keygen2.test;

import java.math.BigInteger;

import java.util.Date;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ImageData;

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

public class keyopreq_enc
  {

    private static void show ()
      {
        System.out.println ("keyopreq_enc out_file\n");
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

       KeyInitializationRequestEncoder.PUKPolicy puk = kre.createPUKPolicy ("123456", PassphraseFormats.NUMERIC, 3, true);

       KeyInitializationRequestEncoder.PINPolicy pin = kre.createPINPolicy (PassphraseFormats.NUMERIC,
                                                           5,
                                                           8,
                                                           3).
                                                           setGrouping (PINGrouping.SHARED).
                                                           setPatternRestrictions (new PatternRestrictions[]
                                                             {PatternRestrictions.THREE_IN_A_ROW,
                                                              PatternRestrictions.SEQUENCE});

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048),
                       null, null).setExportable (true);

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.EC (ECDomains.P_256),
                       pin,
                       puk);

        kre.createKey (KeyGen2KeyUsage.SYMMETRIC_KEY,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                       pin,
                       puk);

        kre.createKey (KeyGen2KeyUsage.SIGNATURE,
                       new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048, BigInteger.valueOf (3)),
                       pin,
                       puk);
                                                           
        kre.createKeyWithPresetPIN (KeyGen2KeyUsage.UNIVERSAL,
                                    new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                                    kre.createPINPolicy (PassphraseFormats.NUMERIC,
                                                                              6,
                                                                              6,
                                                                              3).setGrouping (PINGrouping.SHARED),
                                    puk,
                                    "045227",
                                    true,
                                    true);

        kre.createDevicePINProtectedKey (KeyGen2KeyUsage.AUTHENTICATION,
                                         new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048));

        kre.createKey (KeyGen2KeyUsage.AUTHENTICATION,
                        new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (1024),
                        null, null);

        KeyInitializationRequestEncoder.ManageObject kmc = kre.createManageObject ();
        kmc.deleteKey ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"), true);
        kmc.cloneKey ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
                      KeyGen2KeyUsage.AUTHENTICATION,
                      new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (2048));
        kmc.replaceKey ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
                        KeyGen2KeyUsage.UNIVERSAL,
                        new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (512));
        kmc.updatePINPolicy ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
            kre.createPINPolicy (PassphraseFormats.ALPHANUMERIC,
                                                           6,
                                                           10,
                                                           3).
                                                           setGrouping (PINGrouping.SHARED).
                                                           setPatternRestrictions (new PatternRestrictions[]
                                                             {PatternRestrictions.THREE_IN_A_ROW,
                                                              PatternRestrictions.SEQUENCE,
                                                              PatternRestrictions.MISSING_GROUP}).
                                                           setCachingSupport (true).
                                                           setInputMethod (InputMethods.PROGRAMMATIC), true);
        kmc.updatePUKPolicy ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
            kre.createPUKPolicy ("1092601626770013526152762718826881666260144", PassphraseFormats.NUMERIC, 3, true));
        kmc.updatePresetPIN ((X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"), "12345", true, true);
        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        kmc.signManageObject (signer);
        kmc = kre.createManageObject ();
        kmc.deleteKeysByContent ().setEmailAddress ("john.doe@example.com");
        JKSSignCertStore signer2 = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer2.setKey (null, DemoKeyStore.getSignerPassword ());
        kmc.signManageObject (signer2);
//        kre.setOutputEncryptionCertificate (true);
/*                                                           
        SignerInterface signer3 = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer3.setKey (null, DemoKeyStore.getSignerPassword ());
        kre.signRequest (signer3);
*/

        kre.writeXML();
        return kre;
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        ArrayUtil.writeFile (args[0], create ().writeXML());
      }
  }
