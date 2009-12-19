package org.webpki.keygen2.test;

import java.io.IOException;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.CertificateInfo;

import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.PatternRestrictions;

public class keyopreq_dec
  {
    
    private static void show ()
      {
        System.out.println ("keyopreq_dec in_file\n");
        System.exit (3);
      }


    static void getBaseKeyData (StringBuffer s, KeyOperationRequestDecoder.KeyProperties rk) throws IOException
      {
        KeyOperationRequestDecoder.RSA rsa = (KeyOperationRequestDecoder.RSA) rk.getKeyAlgorithmData ();
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
        cache.addWrapper (KeyOperationRequestDecoder.class);
        KeyOperationRequestDecoder kgrd = (KeyOperationRequestDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        for (KeyOperationRequestDecoder.RequestObjects ro : kgrd.getRequestObjects ())
          {
            System.out.println ();
            StringBuffer s = new StringBuffer ();
            if (ro instanceof KeyOperationRequestDecoder.CreateKey)
              {

                // Standard key generation request

                KeyOperationRequestDecoder.CreateKey rk = (KeyOperationRequestDecoder.CreateKey) ro;
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

                X509Certificate ca = ((KeyOperationRequestDecoder.ManageObject) ro).getCACertificate ();
                String ca_name = "\"" + new CertificateInfo (ca).getSubject () + "\"";
                if (ro instanceof KeyOperationRequestDecoder.CertificateReference)
                  {

                    // Implement this...

                    s.append ("\nLooking for a certificate with SHA1=" +
                                        DebugFormatter.getHexString (((KeyOperationRequestDecoder.CertificateReference)ro).getCertificateSHA1 ()) +
                                        " matching the CA-certificate\n");
                  }

                // "Execute" key management ops...

                if (ro instanceof KeyOperationRequestDecoder.DeleteKey)
                  {
                    KeyOperationRequestDecoder.DeleteKey delk = (KeyOperationRequestDecoder.DeleteKey) ro;
                    s.append ("DK=" + ca_name  + (delk.isConditional () ? " [conditionally]":""));
                  }
                else if (ro instanceof KeyOperationRequestDecoder.DeleteKeysByContent)
                  {
                    KeyOperationRequestDecoder.DeleteKeysByContent dkbc = (KeyOperationRequestDecoder.DeleteKeysByContent) ro;
                    s.append ("DKBC=" + ca_name + " Email=" + dkbc.getEmailAddress ());
                  }
                else if (ro instanceof KeyOperationRequestDecoder.CloneKey)
                  {
                    s.append ("CK=" + ca_name);
                    getBaseKeyData (s, ((KeyOperationRequestDecoder.CloneKey) ro).getCreateKeyProperties ());
                  }
                else if (ro instanceof KeyOperationRequestDecoder.ReplaceKey)
                  {
                    s.append ("RK=" + ca_name);
                    getBaseKeyData (s, ((KeyOperationRequestDecoder.ReplaceKey) ro).getCreateKeyProperties ());
                  }
                else if (ro instanceof KeyOperationRequestDecoder.UpdatePINPolicy)
                  {
                    KeyOperationRequestDecoder.UpdatePINPolicy upg = (KeyOperationRequestDecoder.UpdatePINPolicy) ro;
                    s.append ("UPIN=" + ca_name);
                    s.append (" PIN Group=" + upg.getPINPolicy ().getFormat ());
                  }
                else if (ro instanceof KeyOperationRequestDecoder.UpdatePUKPolicy)
                  {
                    KeyOperationRequestDecoder.UpdatePUKPolicy upg = (KeyOperationRequestDecoder.UpdatePUKPolicy) ro;
                    s.append ("UPUK=" + ca_name);
                    s.append (" PUK Group=" + upg.getPUKPolicy ().getFormat () + " V=");
                  }
                else if (ro instanceof KeyOperationRequestDecoder.UpdatePresetPIN)
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
