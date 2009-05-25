package org.webpki.keygen2.test;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.SymmetricKeyDecrypter;

public class credepreq_dec
  {

    static class RSADec implements SymmetricKeyDecrypter
      {
        public byte[] decrypt (byte[] data, X509Certificate optional_key_id) throws IOException, GeneralSecurityException
          {
            Cipher crypt = Cipher.getInstance ("RSA/ECB/PKCS1Padding");
            crypt.init (Cipher.DECRYPT_MODE, DemoKeyStore.getMarionKeyStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
            if (optional_key_id != null)
              {
                if (!DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey").equals (optional_key_id))
                  {
                    throw new IOException ("Master Key mismatch");
                  }
              }
            return crypt.doFinal (data);
          }
      }
    
    private static void show ()
      {
        System.out.println ("credepreq_dec in_file\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (CredentialDeploymentRequestDecoder.class);
        cache.addWrapper (CustomExt.class);
        CredentialDeploymentRequestDecoder kgrd = (CredentialDeploymentRequestDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        for (CredentialDeploymentRequestDecoder.CertifiedPublicKey cred : kgrd.getCertifiedPublicKeys ())
          {
            StringBuffer properties = new StringBuffer ();
            for (CredentialDeploymentRequestDecoder.PropertyBag property_bag : cred.getPropertyBags ())
              {
                for (CredentialDeploymentRequestDecoder.Property property : property_bag.getProperties ())
                  {
                    properties.append ("\n  Prop t=").append (property_bag.getType ()).
                                    append (" n=").append (property.getName ()).append (" v=").
                    append (property.getValue ()).append (property.isWritable () ? " [R/W]" : " [R]");
                  }
              }
            if (cred.hasSymmetricKey ())
              {
                properties.append ("\n  SymKey=").append (DebugFormatter.getHexString(cred.getSymmetricKey (new RSADec ()))).
                           append (" Alg=");
                for (String s : cred.getSymmetricKeyEndorsedAlgorithms ())
                  {
                    properties.append (s);
                  }
              }
            if (cred.getExtensions ().length != 0)
              {
                if (cred.getExtensions ()[0].getType ().equals (new CustomExt ().namespace ()))
                  {
                    properties.append (" XML Ext=").append  (cache.parse (cred.getExtensions ()[0].getData ()).namespace ());
                  }
                else
                  {
                    properties.append (" BIN Ext=").append  (cred.getExtensions ()[0].getType ());
                  }
              }
            if (cred.isSigned ())
              {
                properties.append (" /SIGN");
              }
            String logotypes = "";
            for (CredentialDeploymentRequestDecoder.Logotype lt : cred.getLogotypes ())
              {
                logotypes += " /LOGO=" + lt.getType ();
              }
            String renewal = cred.getRenewalService () == null ? "" : " /REN (" + cred.getRenewalService ().getNotifyDaysBeforeExpiry () + ")";
            System.out.println ("ID=" +  cred.getID () + " Path=" + cred.getCertificatePath ().length + renewal + logotypes + properties.toString ());
          }
        if (kgrd.isSigned ())
          {
            JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
            verifier.setTrustedRequired (false);
            kgrd.verifySignature (verifier);
            System.out.println ("\nSIGNATURE\n" + verifier.getSignerCertificateInfo ().toString () + "\nSIGNATURE");
          }

      }
  }
