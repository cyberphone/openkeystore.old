package org.webpki.keygen2.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;

import org.webpki.crypto.JKSSignCertStore;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.ECKeys;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.ProvisioningSessionResponseEncoder;

public class provsessres_enc
  {

    private static void show ()
      {
        System.out.println ("provsessres_enc out_file\n");
        System.exit (3);
      }

    static ProvisioningSessionResponseEncoder create () throws Exception
      {
        Date server_time = DOMReaderHelper.parseDateTime (Constants.SERVER_TIME).getTime ();
        Date client_time = DOMReaderHelper.parseDateTime (Constants.CLIENT_TIME).getTime ();

        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getECDSAStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        byte[] session_attestation = signer.signData (Constants.SESSION_DATA, SignatureAlgorithms.ECDSA_SHA256);
        ProvisioningSessionResponseEncoder kre =
                    new ProvisioningSessionResponseEncoder (ECKeys.PUBLIC_KEY2,
                                                            Constants.REQUEST_ID,
                                                            Constants.SESSION_ID,
                                                            server_time,
                                                            client_time,
                                                            session_attestation,
                                                            new X509Certificate[]{(X509Certificate) DemoKeyStore.getECDSAStore ().getCertificate ("mykey")});
        kre.signRequest (new SymKeySignerInterface ()
          {
            public MacAlgorithms getMacAlgorithm () throws IOException, GeneralSecurityException
              {
                return MacAlgorithms.HMAC_SHA256;
              }

            public byte[] signData (byte[] data) throws IOException, GeneralSecurityException
              {
                return MacAlgorithms.HMAC_SHA256.digest (Constants.SESSION_KEY, data);
              }
          });

        return kre;

       }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ArrayUtil.writeFile (args[0], create ().writeXML());
      }
  }
