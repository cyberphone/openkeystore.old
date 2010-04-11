package org.webpki.keygen2.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Signature;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.ECKeys;

import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.keygen2.ProvisioningSessionResponseDecoder;

public class provsessres_dec
  {
    
    private static void show ()
      {
        System.out.println ("provsessres_dec in_file\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (ProvisioningSessionResponseDecoder.class);
        ProvisioningSessionResponseDecoder kgrd = (ProvisioningSessionResponseDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        if (!kgrd.getClientEphemeralKey ().equals (ECKeys.PUBLIC_KEY2))
          {
            System.out.println ("Not same EC");
          }
        kgrd.verifySignature (new SymKeyVerifierInterface ()
          {
            public boolean verifyData (byte[] data, byte[] digest, MacAlgorithms algorithm) throws IOException, GeneralSecurityException
              {
                if (algorithm != MacAlgorithms.HMAC_SHA256)
                  {
                    throw new IOException ("Bad alg");
                  }
                return ArrayUtil.compare (MacAlgorithms.HMAC_SHA256.digest (Constants.SESSION_KEY, data), digest);
              }
          });
        Signature verifier = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
        verifier.initVerify (kgrd.getDeviceCertificatePath ()[0]);
        verifier.update (Constants.SESSION_DATA);
        if (!verifier.verify (kgrd.getSessionAttestation ()))
          {
            throw new RuntimeException ("Bad sign");
          }
        if (!kgrd.getServerTime ().equals (DOMReaderHelper.parseDateTime (Constants.SERVER_TIME).getTime ()))
          {
            throw new RuntimeException ("Bad time");
          }
        java.util.GregorianCalendar gc = new java.util.GregorianCalendar ();
        java.util.Date dt = new java.util.Date ();
        gc.setTimeInMillis (dt.getTime ());
        
        System.out.println ("time=" +gc.get (java.util.Calendar.DST_OFFSET) + " " +
            gc.get (java.util.Calendar.ZONE_OFFSET));
 
      }
  }
