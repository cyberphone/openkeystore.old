package org.webpki.keygen2.test;

import java.io.IOException;


import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.PatternRestrictions;

public class keyinitreq_dec
  {
    
    private static void show ()
      {
        System.out.println ("keyinitreq_dec in_file\n");
        System.exit (3);
      }


    static void getBaseKeyData (StringBuffer s, KeyInitializationRequestDecoder.KeyObject rk) throws IOException
      {
        if (rk.getKeyAlgorithmData () instanceof KeyInitializationRequestDecoder.RSA)
          {
            KeyInitializationRequestDecoder.RSA rsa = (KeyInitializationRequestDecoder.RSA) rk.getKeyAlgorithmData ();
            s.append (" RSA=").append (rsa.getKeySize ());
            if (rsa.getFixedExponent () != null)
              {
                s.append ("/").append (rsa.getFixedExponent ());
              }
          }
        else
          {
            s.append (" ECC=").append (((KeyInitializationRequestDecoder.EC) rk.getKeyAlgorithmData ()).getNamedCurve ());
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
        for (KeyInitializationRequestDecoder.KeyObject rk : kgrd.getKeyObjects ())
          {
            System.out.println ();
            StringBuffer s = new StringBuffer ();
            if (rk.isStartOfPUKPolicy ())
              {
                s.append ("PUK Group=").append ('\n');
              }
            if (rk.isStartOfPINPolicy ())
              {
                s.append ("PIN Group=" + rk.getPINPolicy ().getFormat ());
                PatternRestrictions[] prest = rk.getPINPolicy ().getPatternRestrictions ().toArray (new PatternRestrictions[0]);
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
