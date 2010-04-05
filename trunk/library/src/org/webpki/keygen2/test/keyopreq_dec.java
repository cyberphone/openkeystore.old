package org.webpki.keygen2.test;

import java.io.IOException;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.CertificateInfo;

import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.PatternRestrictions;

public class keyopreq_dec
  {
    
    private static void show ()
      {
        System.out.println ("keyopreq_dec in_file\n");
        System.exit (3);
      }


    static void getBaseKeyData (StringBuffer s, KeyInitializationRequestDecoder.KeyProperties rk) throws IOException
      {
        KeyInitializationRequestDecoder.RSA rsa = (KeyInitializationRequestDecoder.RSA) rk.getKeyAlgorithmData ();
        s.append (" RSA=").append (rsa.getKeySize ());
        if (rsa.getFixedExponent () != null)
          {
            s.append ("/").append (rsa.getFixedExponent ());
          }
        s.append (" USAGE=").append (rk.getKeyUsage ());
        if (rk.isExportable ())
          {
            s.append (" /EXP");
          }
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (KeyInitializationRequestDecoder.class);
        KeyInitializationRequestDecoder kgrd = (KeyInitializationRequestDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        for (KeyInitializationRequestDecoder.RequestObjects ro : kgrd.getRequestObjects ())
          {
            System.out.println ();
            StringBuffer s = new StringBuffer ();
            if (ro instanceof KeyInitializationRequestDecoder.CreateKey)
              {

                // Standard key generation request

                KeyInitializationRequestDecoder.CreateKey rk = (KeyInitializationRequestDecoder.CreateKey) ro;
                if (rk.isStartOfPUKPolicy ())
                  {
                    s.append ("PUK Group=").append ('\n');
                  }
                if (rk.isStartOfPINPolicy ())
                  {
                    s.append ("PIN Group=" + rk.getPINPolicy ().getFormat ());
                    PatternRestrictions[] prest = rk.getPINPolicy ().getPatternRestrictions ();
                    if (prest != null) for (PatternRestrictions pr : prest)
                      {
                        s.append (" PR/").append (pr.toString ());
                      }
                    s.append ('\n');
                  }
                s.append ("CREATE");
                getBaseKeyData (s, rk);
                if (rk.getPresetPIN () != null)
                  {
                    s.append (" V=");
                  }
              }
            else
              {
 
                // This MUST be a key management operation..

                X509Certificate ca = ((KeyInitializationRequestDecoder.ManageObject) ro).getCACertificate ();
                String ca_name = "\"" + new CertificateInfo (ca).getSubject () + "\"";
                if (ro instanceof KeyInitializationRequestDecoder.CertificateReference)
                  {

                    // Implement this...

                    s.append ("\nLooking for a certificate with SHA1=" +
                                        DebugFormatter.getHexString (((KeyInitializationRequestDecoder.CertificateReference)ro).getCertificateSHA1 ()) +
                                        " matching the CA-certificate\n");
                  }

                // "Execute" key management ops...

                if (ro instanceof KeyInitializationRequestDecoder.DeleteKey)
                  {
                    KeyInitializationRequestDecoder.DeleteKey delk = (KeyInitializationRequestDecoder.DeleteKey) ro;
                    s.append ("DK=" + ca_name  + (delk.isConditional () ? " [conditionally]":""));
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.DeleteKeysByContent)
                  {
                    KeyInitializationRequestDecoder.DeleteKeysByContent dkbc = (KeyInitializationRequestDecoder.DeleteKeysByContent) ro;
                    s.append ("DKBC=" + ca_name + " Email=" + dkbc.getEmailAddress ());
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.CloneKey)
                  {
                    s.append ("CK=" + ca_name);
                    getBaseKeyData (s, ((KeyInitializationRequestDecoder.CloneKey) ro).getCreateKeyProperties ());
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.ReplaceKey)
                  {
                    s.append ("RK=" + ca_name);
                    getBaseKeyData (s, ((KeyInitializationRequestDecoder.ReplaceKey) ro).getCreateKeyProperties ());
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePINPolicy)
                  {
                    KeyInitializationRequestDecoder.UpdatePINPolicy upg = (KeyInitializationRequestDecoder.UpdatePINPolicy) ro;
                    s.append ("UPIN=" + ca_name);
                    s.append (" PIN Group=" + upg.getPINPolicy ().getFormat ());
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePUKPolicy)
                  {
                    KeyInitializationRequestDecoder.UpdatePUKPolicy upg = (KeyInitializationRequestDecoder.UpdatePUKPolicy) ro;
                    s.append ("UPUK=" + ca_name);
                    s.append (" PUK Group=" + upg.getPUKPolicy ().getFormat () + " V=");
                  }
                else if (ro instanceof KeyInitializationRequestDecoder.UpdatePresetPIN)
                  {
      //              KeyOperationRequestDecoder.UpdatePresetPIN upg = (KeyOperationRequestDecoder.UpdatePresetPIN) ro;
                    s.append ("UPPRSET=" + ca_name);
                    s.append (" V=");
                  }
              }
            System.out.println (s);
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
