// This is the base class which is extended by "CredentialDeploymentRequest" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Mac;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.MacAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class CredentialDeploymentRequest extends XMLObjectWrapper 
  {
    CredentialDeploymentRequest () {}


    public static String[] getSortedAlgorithms (String[] algorithms) throws IOException
      {
        int i = 0;
        while (true)
          {
            if (i < (algorithms.length - 1))
              {
                if (algorithms[i].compareTo (algorithms[i + 1]) > 0)
                  {
                    String s = algorithms[i];
                    algorithms[i] = algorithms[i + 1];
                    algorithms[i + 1] = s;
                    i = 0;
                  }
                else
                  {
                    i++;
                  }
              }
            else
              {
                break;
              }
          }
        return algorithms;
      }


    byte[] getAlgorithmsMac (byte[] the_key,
                             String key_id, String client_session_id, String server_session_id,
                             String[] algorithms) throws IOException, GeneralSecurityException
      {
        Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
        mac.init (new SecretKeySpec (KeyAttestationUtil.createKA1Nonce (key_id, client_session_id, server_session_id), "RAW"));  // Note: any length is OK in HMACSHA*
        for (String s : getSortedAlgorithms (algorithms))
          {
            mac.update (s.getBytes ("UTF-8"));
            mac.update ((byte)0);
          }
        mac.update (the_key);
        return mac.doFinal ();
      }


    static void checkCertificateOrder (X509Certificate[] eepath, X509Certificate[] capath) throws IOException
      {
        if (!eepath[0].equals (CertificateUtil.getSortedPath (new X509Certificate[]{eepath[0], capath[0]})[0]))
          {
            throw new IOException ("Certificate order error!");
          }
      }


    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (REDUCED_XML_ENC_SCHEMA_FILE);
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    public String element ()
      {
        return "CredentialDeploymentRequest";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
