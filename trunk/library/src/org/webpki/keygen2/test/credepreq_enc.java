package org.webpki.keygen2.test;

import java.util.Date;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ImageData;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.wasp.test.BankLogo;
 
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSSignCertStore;

import org.webpki.keygen2.CredentialDeploymentRequestEncoder;
import org.webpki.keygen2.ServerCredentialStore;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.MACInterface;

public class credepreq_enc
  {

    static int key_count;
    private static void show ()
      {
        System.out.println ("credepreq_enc out_file\n");
        System.exit (3);
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ServerCredentialStore ics = new  ServerCredentialStore (Constants.SESSION_ID,
                                                                Constants.REQUEST_ID);
        ServerCredentialStore.KeyProperties kp = ics.createKey (KeyGen2KeyUsage.AUTHENTICATION,
            new ServerCredentialStore.KeyAlgorithmData.RSA (2048),
            null).setExportable (true).setSymmetricKey (new byte[]{3,4,5}, new String[]{"http://host/fdfdf"});
        
        kp.setCertificatePath (new X509Certificate[] {(X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
            (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificateChain ("mykey")[1]}).
            addExtension ("http://ext/hhh", new byte[]{3,3,3,3,3,3,3,3,3,3,3}).
            addLogotype (KeyGen2URIs.LOGOTYPES.APPLICATION, new ImageData (BankLogo.getGIFImage (), "image/gif")).
            addEncryptedExtension ("http://ext/hhh1", new byte[]{3,3,3,3,3,3,3,3,3,3,3}).
            addPropertyBag ("http://hhj/prop").
            addProperty ("digits", "1234", true).
            addProperty ("hug", "lame", false);
 


        CredentialDeploymentRequestEncoder cde = 
                                   new CredentialDeploymentRequestEncoder ("https://ca.example.com/keygenres",
                                       ics,
                                       new MACInterface ()
                                   {

                                    @Override
                                    public byte[] getMac (byte[] data) throws IOException, GeneralSecurityException
                                      {
                                         return new byte[]{0,1,2,4};
                                      }
                                     
                                   });
/*
        
        cde.addCertifiedPublicKey ("Key.1",
                   (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"));

        X509Certificate[] two = new X509Certificate[] {(X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
                                                       (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificateChain ("mykey")[1]};
        cde.addCertifiedPublicKey ("Key.2", two).
                    setRenewalServiceData (14, new String[] {"http://ca.mybank.com/update"}, null).
                    addLogotype (new ImageData (BankLogo.getGIFImage (), "image/gif"), KeyGen2URIs.LOGOTYPES.APPLICATION);
        cde.addCertifiedPublicKey ("Key.3",
                   (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey")).
                    setSymmetricKey (new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
                                     new String[]{"http://www.w3.org/2000/09/xmldsig#hmac-sha1"}).addPropertyBag ("urn:otpstd:spec").
                    addProperty ("login", "janedoe", false).
                    addProperty ("digits", "8", false).
                    addProperty ("counter", "456", true);
        XMLObjectWrapper xml_ext = new CustomExt ();
        cde.addCertifiedPublicKey ("Key.4",
                   (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey")).
                         addExtension (xml_ext.writeXML (), xml_ext.namespace ());

        JKSSignCertStore ksigner = new JKSSignCertStore (DemoKeyStore.getSubCAKeyStore (), null);
        ksigner.setKey (null, DemoKeyStore.getSignerPassword ());
        cde.addCertifiedPublicKey ("Key.5",
                   (X509Certificate)DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey")).
                         addExtension (new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, "http://java.com/bytecode").
                         signCertifiedPublicKey (ksigner);

        JKSSignCertStore rsigner = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        rsigner.setKey (null, DemoKeyStore.getSignerPassword ());
//        cde.signRequest (rsigner);

 */

        ArrayUtil.writeFile (args[0], cde.writeXML());
      }
  }
