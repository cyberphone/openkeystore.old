package org.webpki.infocard.test;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ImageData;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.wasp.test.BankLogo;

import org.webpki.crypto.JKSSignCertStore;

import org.webpki.infocard.InfoCardWriter;
import org.webpki.infocard.TokenType;
import org.webpki.infocard.ClaimType;

public class writecard
  {

    private static void show ()
      {
        System.out.println ("writecard out_file\n");
        System.exit (3);
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        InfoCardWriter icw = new InfoCardWriter ((X509Certificate) DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
                                                 TokenType.SAML_1_0,
                                                 "http://infocard.example.com/1234567",
                                                 "http://example.com",
                                                 "https://sts.example.com/tokenservice",
                                                 "https://sts.example.com/metadata");
        icw.setDisplayCredentialHint ("Insert smart card")
           .addClaim (ClaimType.EMAIL_ADDRESS, "boss@fire.hell")
           .addClaim (ClaimType.COUNTRY)
           .setCardName ("WebPKI.org")
           .setCardImage (new ImageData (BankLogo.getGIFImage (), "image/gif"))
  //         .setTimeExpires (DOMReaderHelper.parseDateTime ("2017-11-12T21:03:24Z").getTime ())
           .setRequireAppliesTo (true)
           .setOutputSTSIdentity (true)
           .setPrivacyNotice ("http://example.com/priv")
           .addTokenType (TokenType.SAML_2_0);


        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        ArrayUtil.writeFile (args[0], icw.getInfoCard (signer));
      }
  }
