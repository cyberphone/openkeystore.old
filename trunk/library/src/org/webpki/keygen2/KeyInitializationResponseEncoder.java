package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;
import java.util.Vector;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLAsymKeySigner;
import org.webpki.xmldsig.XMLEnvelopedInput;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


@SuppressWarnings("serial")
public class KeyInitializationResponseEncoder extends KeyInitializationResponse
  {
    public static class KeyArchivalData
      {
        byte[] encrypted_private_key;

        byte[] wrapped_encryption_key;

        SymEncryptionAlgorithms encrypt_algorithm;

        AsymEncryptionAlgorithms key_wrap_algorithm;
        

        KeyArchivalData () {}  // Not used...

        public KeyArchivalData (byte[] encrypted_private_key,
                           byte[] wrapped_encryption_key,
                           SymEncryptionAlgorithms encrypt_algorithm,
                           AsymEncryptionAlgorithms key_wrap_algorithm)
          {
            this.encrypted_private_key = encrypted_private_key;
            this.wrapped_encryption_key = wrapped_encryption_key;
            this.encrypt_algorithm = encrypt_algorithm;
            this.key_wrap_algorithm = key_wrap_algorithm;
          }

      }

    private String request_url;

    private String submit_url;

    private String client_session_id;

    private String server_session_id;

    private Date client_time;

    private String server_time;

    private byte[] server_certificate_fingerprint;

    private Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey> ();

    private ServerCookie server_cookie;  // Optional

    private String prefix;  // Default: no prefix

    private Element insert_elem;

    private X509Certificate[] device_key_attestation_key;

    private X509Certificate[] device_encryption_key;

    private String key_attestation_algorithm = KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1;

    private boolean need_xenc_namespace;

    private boolean need_ds11_namespace;


    private class GeneratedPublicKey extends XMLObjectWrapper implements XMLEnvelopedInput
      {
        String id;

        PublicKey attested_public_key;          // defined for attested keys only

        byte[] attest_signature;                // defined for attested keys only

        KeyArchivalData archival_data;                 // defined for attested and archivalable keys only

        GeneratedPublicKey (String id)
          {
            this.id = id;
            generated_keys.add (this);
          }

        public String getReferenceURI ()
          {
            return id; 
          }


        public Element getInsertElem ()
          {
            return null;
          }


        public XMLSignatureWrapper getSignature ()
          {
            return null;
          }


        protected void toXML (DOMWriterHelper wr) throws IOException
          {
            wr.initializeRootObject (prefix);

            wr.setStringAttribute (ID_ATTR, id);
            if (attested_public_key != null)
              {
                wr.setBinaryAttribute (KEY_ATTESTATION_ATTR, attest_signature);
                XMLSignatureWrapper.writePublicKey (wr, attested_public_key);

                if (archival_data != null)
                  {
                    String key_name = id + ".Private";
                    wr.addChildElement (ENCRYPTED_PRIVATE_KEY_ELEM);
                    wr.setStringAttribute (FORMAT_ATTR, KeyGen2URIs.FORMATS.PKCS8_PRIVATE_KEY_INFO);

                    wr.pushPrefix (XML_ENC_NS_PREFIX);

                    wr.addChildElementNS (XML_ENC_NS, ENCRYPTED_KEY_ELEM);
                    XMLEncUtil.setEncryptionMethod (wr, archival_data.encrypt_algorithm);
                    wr.pushPrefix (XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
                    wr.addChildElementNS (XMLSignatureWrapper.XML_DSIG_NS, XMLSignatureWrapper.KEY_INFO_ELEM);
                    wr.addString (XMLSignatureWrapper.KEY_NAME_ELEM, key_name);
                    wr.getParent ();
                    wr.popPrefix ();
                    XMLEncUtil.setCipherData (wr, archival_data.encrypted_private_key);
                    wr.getParent ();

                    wr.addChildElementNS (XML_ENC_NS, ENCRYPTED_KEY_ELEM);
                    XMLEncUtil.setEncryptionMethod (wr, archival_data.key_wrap_algorithm);
                    XMLEncUtil.setCipherData (wr, archival_data.wrapped_encryption_key);
                    wr.addString (CARRIED_KEY_NAME_ELEM, key_name);
                    wr.getParent ();

                    wr.popPrefix ();

                    wr.getParent ();
                  }
              }
          }


        public void init () throws IOException
          {
            addSchema (KEYGEN2_SCHEMA_FILE);
          }


        public Document getEnvelopeRoot () throws IOException
          {
            return getRootDocument ();
          }


        public Element getTargetElem () throws IOException
          {
            return null;
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
            return GENERATED_PUBLIC_KEY_ELEM;
          }


        protected void fromXML (DOMReaderHelper helper) throws IOException
          {
            throw new IOException ("Should have been implemented in derived class");
          }

      }


    public void addSelfSignedKey (AsymKeySignerInterface signing_key, String id) throws IOException
      {
        GeneratedPublicKey gk = new GeneratedPublicKey (id);
        gk.forcedDOMRewrite ();
        XMLAsymKeySigner xml_signer = new XMLAsymKeySigner (signing_key);
        xml_signer.setSignedKeyInfo (true);
        xml_signer.removeXMLSignatureNS ();
        xml_signer.createEnvelopedSignature (gk);
        gk.getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
      }


    public void addAttestedKey (PublicKey attested_public_key, byte[] attest_signature, String id, KeyArchivalData optional_archival_data) throws IOException
      {
        GeneratedPublicKey gk = new GeneratedPublicKey (id);
        gk.attested_public_key = attested_public_key;
        if (attested_public_key instanceof ECPublicKey)
          {
            need_ds11_namespace = true;
          }
        gk.attest_signature = attest_signature;
        if ((gk.archival_data = optional_archival_data) != null)
          {
            need_xenc_namespace = true;
          }
        gk.getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    @SuppressWarnings("unused")
    private KeyInitializationResponseEncoder () {}


    public KeyInitializationResponseEncoder (String client_session_id, String server_session_id, String request_url, String submit_url, String server_time, Date client_time, X509Certificate optional_server_certificate) throws IOException
      {
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
        this.submit_url = submit_url;
        this.request_url = request_url;
        this.server_time = server_time;
        this.client_time = client_time;
        if (optional_server_certificate != null)
          {
            this.server_certificate_fingerprint = CertificateUtil.getCertificateSHA256 (optional_server_certificate);
          }
      }


    public void setKeyAttestationAlgorithm (String key_attestation_algorithm_uri)
      {
        this.key_attestation_algorithm = key_attestation_algorithm_uri;
      }


    public void setDeviceKeyAttestationKey (X509Certificate[] certificate_path)
      {
        this.device_key_attestation_key = certificate_path;
      }


    public void setDeviceEncryptionKey (X509Certificate[] certificate_path)
      {
        this.device_encryption_key = certificate_path;
      }


    public void createEndorsementKeySignature (SignerInterface signer) throws IOException
      {
        forcedDOMRewrite ();
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        ds.createEnvelopedSignature (getRootDocument (), client_session_id, null, insert_elem);
      }


    private void conditionalKeyOutput (DOMWriterHelper wr, X509Certificate[] certificate_path, String element) throws IOException
      {
        if (certificate_path != null)
          {
            wr.addChildElement (element);
            XMLSignatureWrapper.writeX509DataSubset (wr, CertificateUtil.getSortedPath (certificate_path));
            wr.getParent ();
          }
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (need_ds11_namespace)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        if (need_xenc_namespace)
          {
            XMLEncUtil.addXMLEncNS (wr);
          }

        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

        wr.setStringAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        wr.setStringAttribute (REQUEST_URL_ATTR, request_url);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);

        if (server_certificate_fingerprint != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
          }

        boolean attest_key_needed = false;
        for (GeneratedPublicKey gk : generated_keys)
          {
            if (gk.attest_signature == null)
              {
                if (attest_key_needed)
                  {
                    throw new IOException ("Missing attestation for key: " + gk.id);
                  }
              }
            else
              {
                attest_key_needed = true;
              }
            wr.addWrapped (gk);
          }

        conditionalKeyOutput (wr, device_encryption_key, DEVICE_ENCRYPTION_KEY_ELEM);

        conditionalKeyOutput (wr, device_key_attestation_key, DEVICE_KEY_ATTESTATION_KEY_ELEM);

        insert_elem = wr.addChildElement (ENDORSEMENT_KEY_ELEM);
        if (attest_key_needed)
          {
            wr.setStringAttribute (KEY_ATTESTATION_ALGORITHM_ATTR, key_attestation_algorithm);
          }
        wr.getParent ();

        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
