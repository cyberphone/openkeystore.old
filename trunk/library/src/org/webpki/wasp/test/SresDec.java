package org.webpki.wasp.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.AuthorityInfoAccessCAIssuersCache;

import org.webpki.wasp.prof.xds.XDSProfileResponseDecoder;  // Mandatory profile

import org.webpki.wasp.SignatureResponseDecoder;
import org.webpki.wasp.SignatureProfileResponseDecoder;


public class SresDec
  {

    private static void show ()
      {
        System.out.println ("SresDec inputfile [-a]\n    -a  aia support\n");
        System.exit (3);
      }

    static SignatureResponseDecoder test (String in_file, boolean aia_support) throws Exception
      {
        byte[] data = ArrayUtil.readFile (in_file);
        XMLSchemaCache schema_cache = new XMLSchemaCache ();
        schema_cache.addWrapper (SignatureResponseDecoder.class);
        schema_cache.addWrapper (XDSProfileResponseDecoder.class);

        SignatureResponseDecoder sres = (SignatureResponseDecoder) schema_cache.parse (data);

        SignatureProfileResponseDecoder prdec = sres.getSignatureProfileResponseDecoder ();

        JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);
        if (aia_support)
          {
            verifier.setAuthorityInfoAccessCAIssuersHandler (new AuthorityInfoAccessCAIssuersCache ());
          }

        prdec.verifySignature (verifier);

        System.out.println ("\nUSER SIGNATURE VERIFIED\n" + verifier.getSignerCertificateInfo ().toString ());
        return sres;
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[1].equals ("-a"))) show ();
        test (args[0], args.length == 2);
      }

  }
