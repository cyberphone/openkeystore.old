package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import java.util.GregorianCalendar;
import java.util.Vector;

import java.security.PublicKey;
import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLAsymKeyVerifier;
import org.webpki.xmldsig.SignedKeyInfoSpecifier;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.EncryptionAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationResponseDecoder extends KeyInitializationResponse implements Serializable
  {
    private static final long serialVersionUID = 1L;

    private String client_session_id;

    private String server_session_id;

    private String submit_url;

    private String request_url;

    private GregorianCalendar server_time;

    private GregorianCalendar client_time;

    private ServerCookie server_cookie;                         // Optional

    private byte[] server_certificate_fingerprint;              // Optional

    private XMLSignatureWrapper ek_signature;                   // Optional

    private Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey> ();

    private String key_attestation_algorithm;

    private X509Certificate[] device_key_attestation_key;

    @SuppressWarnings("unused")
    private X509Certificate[] device_encryption_key;

    boolean key_attestations;


    public class KeyArchivalData implements Serializable
      {
        private static final long serialVersionUID = 1L;

        private KeyArchivalData () {}

        byte[] encrypted_private_key;

        byte[] wrapped_encryption_key;

        SymEncryptionAlgorithms encryption_algorithm;

        AsymEncryptionAlgorithms key_wrap_algorithm;
        
        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }


        public byte[] getWrappedEncryptionKey ()
          {
            return wrapped_encryption_key;
          }


        public SymEncryptionAlgorithms getEncryptionAlgorithm ()
          {
            return encryption_algorithm;
          }


        public AsymEncryptionAlgorithms getKeyWrapAlgorithm ()
          {
            return key_wrap_algorithm;
          }

      }


    public class GeneratedPublicKey implements Serializable
      {
        private static final long serialVersionUID = 1L;

        private GeneratedPublicKey () {}

        String id;

        PublicKey public_key;

        byte[] key_attestation;

        KeyArchivalData archival_data;


        public String getID ()
          {
            return id;
          }


        public PublicKey getPublicKey ()
          {
            return public_key;
          }

        public KeyArchivalData getKeyArchivalData ()
          {
            return archival_data;
          }

      }


    private X509Certificate[] conditionalKeyInput (DOMReaderHelper rd, String element) throws IOException
      {
        X509Certificate[] certificate_path = null;
        if (rd.hasNext (element))
          {
            rd.getNext (element);
            rd.getChild ();
            certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);
            rd.getParent ();
          }
        return certificate_path;
      }


    public GeneratedPublicKey[] getGeneratedPublicKeys ()
      {
        return generated_keys.toArray (new GeneratedPublicKey[0]);
      }


    public boolean hasEndorsementKeySignature ()
      {
        return ek_signature != null;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public byte[] getServerCertificateFingerprint ()
      {
        return server_certificate_fingerprint;
      }


    public X509Certificate[] getDeviceKeyAttestationKey ()
      {
        return device_key_attestation_key;
      }

    
    public String getSubmitURL ()
      {
        return submit_url;
      }


    public String getRequestURL ()
      {
        return request_url;
      }
 

    public GregorianCalendar getServerTime ()
      {
        return server_time;
      }


    public GregorianCalendar getClientTime ()
      {
        return client_time;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public void verifyEndorsementKeySignature (VerifierInterface verifier,
                                               KeyInitializationRequestEncoder keyopreq) throws IOException
      {
        XMLVerifier ds = new XMLVerifier (verifier);
        ds.setSignedKeyInfo (SignedKeyInfoSpecifier.ALLOW_SIGNED_KEY_INFO);
        ds.validateEnvelopedSignature (this, null, ek_signature, client_session_id);
        if (key_attestations) 
          {
            if (device_key_attestation_key == null)
              {
                device_key_attestation_key = verifier.getSignerCertificatePath ();
              }
            else
              {
                if (!device_key_attestation_key[0].equals (verifier.getSignerCertificatePath ()[0]))
                  {
                    throw new IOException ("Non-matching key attestation key certificate");
                  }
              }
            String key_id = null;
            try
              {
                if (generated_keys.size () != keyopreq.requested_keys.size ())
                  {
                    throw new IOException ("Wrong number of keys in response");
                  }
                for (GeneratedPublicKey gk : generated_keys)
                  {
                    key_id = gk.id;
                    KeyInitializationRequestEncoder.KeyProperties rk = keyopreq.requested_keys.get (gk.id);
                    if (rk == null)
                      {
                        throw new GeneralSecurityException ("Response key missing");
                      }
                    if (gk.key_attestation == null)
                      {
                        throw new GeneralSecurityException ("Missing attestation on key");
                      }
// TODO
/*
                    byte[] nonce = KeyAttestationUtil.createKA1Nonce (gk.id,
                                                                      client_session_id,
                                                                      server_session_id);
                    KeyAttestationUtil.verifyKA1Signature (gk.key_attestation,
                                                           device_key_attestation_key[0].getPublicKey(),
                                                           gk.public_key,
                                                           rk.exportable,
                                                           rk.key_usage,
                                                           nonce,
                                                           rk.archival_key == null ? null : rk.archival_key.getPublicKey ());
*/
                  }
              }
            catch (GeneralSecurityException gse)
              {
                String error = gse.getMessage ();
                throw new IOException (key_id == null ? error : "Related to key[" + key_id + "]: " + error);
              }
          }
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        client_time = ah.getDateTime (CLIENT_TIME_ATTR);

        server_certificate_fingerprint = ah.getBinaryConditional (SERVER_CERT_FP_ATTR);
        if (request_url.startsWith ("https://") && server_certificate_fingerprint == null)
          {
            throw new IOException ("Missing: " + SERVER_CERT_FP_ATTR);
          }

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        do
          {
            GeneratedPublicKey gk = new GeneratedPublicKey ();
            Element target_elem = rd.getNext (GENERATED_PUBLIC_KEY_ELEM);
            gk.id = ah.getString (ID_ATTR);
            gk.key_attestation = ah.getBinaryConditional (KEY_ATTESTATION_ATTR);
            key_attestations = gk.key_attestation != null;
            rd.getChild ();
            if (rd.hasNext (XMLSignatureWrapper.SIGNATURE_ELEM))
              {
                XMLSignatureWrapper signature = (XMLSignatureWrapper) wrap (rd.getNext ());
                XMLAsymKeyVerifier verifier = new XMLAsymKeyVerifier ();
                verifier.setSignedKeyInfo (SignedKeyInfoSpecifier.ALLOW_SIGNED_KEY_INFO);
                verifier.validateEnvelopedSignature (this, target_elem, signature, gk.id);
                gk.public_key = verifier.getPublicKey ();
               }
            else
              {
                gk.public_key = XMLSignatureWrapper.readPublicKey (rd);
              }
            if (rd.hasNext ())
              {
                gk.archival_data = new KeyArchivalData ();
                rd.getNext (PRIVATE_KEY_ELEM);
                rd.getChild ();

/*
                rd.getNext (ENCRYPTED_KEY_ELEM);
                rd.getChild ();
                gk.archival_data.encryption_algorithm =
                   (SymEncryptionAlgorithms)XMLEncUtil.getEncryptionMethod (rd,
                                                                            new EncryptionAlgorithms[]{SymEncryptionAlgorithms.AES128_CBC,
                                                                                                         SymEncryptionAlgorithms.AES256_CBC});
*/
                rd.getNext (XMLSignatureWrapper.KEY_INFO_ELEM);
                rd.getChild ();
                String key_name = rd.getString (XMLSignatureWrapper.KEY_NAME_ELEM);
                rd.getParent ();
/*
                gk.archival_data.encrypted_private_key = XMLEncUtil.getCipherValue (rd);
                rd.getParent ();

                rd.getNext (ENCRYPTED_KEY_ELEM);
                rd.getChild ();
                gk.archival_data.key_wrap_algorithm =
                   (AsymEncryptionAlgorithms) XMLEncUtil.getEncryptionMethod (rd, new EncryptionAlgorithms[]{AsymEncryptionAlgorithms.RSA_PKCS_1});
                gk.archival_data.wrapped_encryption_key = XMLEncUtil.getCipherValue (rd);
                if (!rd.getString (CARRIED_KEY_NAME_ELEM).equals (key_name))
                  {
                    throw new IOException ("Unexpected symmetric key name: " + key_name);
                  }
*/
                rd.getParent ();

                rd.getParent ();
              }
            rd.getParent ();
            generated_keys.add (gk);
          }
        while (rd.hasNext (GENERATED_PUBLIC_KEY_ELEM));

/*
        device_encryption_key = conditionalKeyInput (rd, DEVICE_ENCRYPTION_KEY_ELEM);

        device_key_attestation_key = conditionalKeyInput (rd, DEVICE_KEY_ATTESTATION_KEY_ELEM);
*/
        rd.getNext (ENDORSEMENT_KEY_ELEM);
        key_attestation_algorithm = ah.getStringConditional (KEY_ATTESTATION_ALGORITHM_ATTR,
                                                             KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1);
        if (key_attestations)
          {
            if (!key_attestation_algorithm.equals (KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1))
              {
                throw new IOException ("Unknown \"" + KEY_ATTESTATION_ALGORITHM_ATTR + "\" :" + key_attestation_algorithm);
              }
          }
        rd.getChild ();
        ek_signature = (XMLSignatureWrapper) wrap (rd.getNext ());
        rd.getParent ();

        if (rd.hasNext ())  // If not ServerCookie XML validation has gone wrong
          {
            server_cookie = ServerCookie.read (rd);
          }
     }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }

  }
