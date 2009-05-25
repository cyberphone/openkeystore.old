package org.webpki.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Vector;
import java.util.HashMap;
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.MacAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class CredentialDeploymentRequestEncoder extends CredentialDeploymentRequest
  {

    public static class PresetValueSecurity
      {
        X509Certificate encryption_certificate;

        AsymEncryptionAlgorithms key_wrap_algorithm;

        SymEncryptionAlgorithms encryption_algorithm;

        public PresetValueSecurity (X509Certificate encryption_certificate,
                                    AsymEncryptionAlgorithms key_wrap_algorithm,
                                    SymEncryptionAlgorithms encryption_algorithm)
          {
            this.encryption_certificate = encryption_certificate;
            this.key_wrap_algorithm = key_wrap_algorithm;
            this.encryption_algorithm = encryption_algorithm;
          }

      }

    private static final String PRESET_VALUE_KEY_NAME = "Master.Key";

    private class Property
      {
        String name;

        String value;

        boolean writable;
      }


    public class PropertyBag
      {
        private PropertyBag () {}

        String type;

        CertifiedPublicKey cpk;

        HashMap<String,Property> properties = new HashMap<String,Property> ();

        public PropertyBag addProperty (String name, String value, boolean writable) throws IOException
          {
            cpk.checkSigned ();
            Property property = new Property ();
            property.name = name;
            property.value = value;
            property.writable = writable;
            if (properties.put (name, property) != null)
              {
                throw new IOException ("Duplicate property name \"" + name + "\" not allowed");
              }
            return this;
          }
      }


    private class Extension
      {
        String type;

        byte[] data;
      }

    private class Logotype
      {
        MimeTypedObject image;

        String type_uri;
      }


    public class CertifiedPublicKey
      {
        String key_id;

        String friendly_name;

        X509Certificate[] certificates;

        HashMap<String,PropertyBag> property_bags = new HashMap<String,PropertyBag> ();

        byte[] symmetric_key;

        String[] endorsed_algorithms;

        int notify_days_before_expiry;

        String[] renewal_urls;

        String[] renewal_dnss;

        Vector<Logotype> logotypes = new Vector<Logotype> ();

        Vector<Extension> extension_objects = new Vector<Extension> ();

        LocalWriter local_writer = new LocalWriter ();

        String piggyback_mac_algorithm;   // Null = default

        boolean signed;


        private CertifiedPublicKey () {}


        private CertifiedPublicKey (String key_id, X509Certificate[] certificates)
          {
            this.key_id = key_id;
            this.certificates = certificates;
          }


        private void checkSigned () throws IOException
          {
            if (signed)
              {
                throw new IOException ("Already signed, nothing can be added!");
              }
          }


        public CertifiedPublicKey setSymmetricKey (byte[] symmetric_key, String[] endorsed_algorithms) throws IOException
          {
            checkSigned ();
            this.symmetric_key = symmetric_key;
            this.endorsed_algorithms = endorsed_algorithms;
            xml_enc = true;
            return this;
          }


        public CertifiedPublicKey setSymmetricKey (byte[] symmetric_key) throws IOException
          {
            return setSymmetricKey (symmetric_key, new String[]{KeyGen2URIs.ALGORITHMS.ANY});
          }


        public CertifiedPublicKey setFriendlyName (String friendly_name) throws IOException
          {
            checkSigned ();
            this.friendly_name = friendly_name;
            return this;
          }


        public CertifiedPublicKey setPiggybackMACAlgorithm (String mac_algorithm) throws IOException
          {
            checkSigned ();
            this.piggyback_mac_algorithm = mac_algorithm;
            return this;
          }


        public CertifiedPublicKey addExtension (byte[] data, String type) throws IOException
          {
            checkSigned ();
            Extension ext = new Extension ();
            ext.data = data;
            ext.type = type;
            this.extension_objects.add (ext);
            return this;
          }


        public PropertyBag addPropertyBag (String type) throws IOException
          {
            checkSigned ();
            PropertyBag property_bag = new PropertyBag ();
            property_bag.cpk = this;
            property_bag.type = type;
            if (property_bags.put (type, property_bag) != null)
              {
                throw new IOException ("Duplicate property bag \"" + type + "\" not allowed!");
              }
            return property_bag;
          }


        public CertifiedPublicKey setRenewalServiceData (int notify_days_before_expiry, String[] renewal_urls, String[] renewal_dnss) throws IOException
          {
            checkSigned ();
            this.notify_days_before_expiry = notify_days_before_expiry;
            this.renewal_urls = renewal_urls;
            this.renewal_dnss = renewal_dnss;
            return this;
          }


        public CertifiedPublicKey addLogotype (MimeTypedObject image, String type_uri) throws IOException
          {
            checkSigned ();
            Logotype logotype = new Logotype ();
            logotype.image = image;
            logotype.type_uri = type_uri;
            logotypes.add (logotype);
            return this;
          }


        public void signCertifiedPublicKey (SignerInterface signer) throws IOException
          {
            CredentialDeploymentRequest.checkCertificateOrder (CertificateUtil.getSortedPath (certificates),
                                                               signer.prepareSigning (false));
            checkSigned ();
            signed = true;
            XMLSigner ds = new XMLSigner (signer);
            ds.removeXMLSignatureNS ();
            local_writer.forcedDOMRewrite ();
            ds.createEnvelopedSignature (local_writer);
          }


        XMLObjectWrapper setupForWrite () throws IOException
          {
            if (!signed)
              {
                local_writer.forcedDOMRewrite ();
              }
            local_writer.getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
            if (signed)
              {
                local_writer.getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
              }
            return local_writer;
          }


        class LocalWriter extends XMLObjectWrapper implements XMLEnvelopedInput
          {

            LocalWriter () {}

            public String getReferenceURI ()
              {
                return key_id; 
              }


            public Element getInsertElem ()
              {
                return null;
              }


            public XMLSignatureWrapper getSignature ()
              {
                return null;
              }


            void writeEncryptedKey (DOMWriterHelper wr, X509Certificate certificate, String key_id) throws IOException
              {
                try
                  {
                    wr.addChildElement (PIGGYBACKED_SYMMETRIC_KEY_ELEM);
                    wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, endorsed_algorithms);
                    wr.setBinaryAttribute (MAC_ATTR, getAlgorithmsMac (symmetric_key, key_id, client_session_id, server_session_id, endorsed_algorithms));
                    if (piggyback_mac_algorithm != null)
                      {
                        wr.setStringAttribute (MAC_ALGORITHM_ATTR, piggyback_mac_algorithm);
                      }

                    wr.pushPrefix (XML_ENC_NS_PREFIX);

                    wr.addChildElementNS (XML_ENC_NS, ENCRYPTED_KEY_ELEM);

                    XMLEncUtil.setEncryptionMethod (wr, AsymEncryptionAlgorithms.RSA_PKCS_1);

                    Cipher crypt = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName ());
                    crypt.init (Cipher.ENCRYPT_MODE, certificate.getPublicKey ());

                    XMLEncUtil.setCipherData (wr, crypt.doFinal (symmetric_key));

                    wr.getParent ();

                    wr.popPrefix ();

                    wr.getParent ();
                  }
                catch (GeneralSecurityException gse)
                  {
                    throw new IOException (gse.getMessage ());
                  }
              }


            protected void toXML (DOMWriterHelper wr) throws IOException
              {
                wr.initializeRootObject (prefix);

                if (signed)
                  {
                    XMLSignatureWrapper.addXMLSignatureNS (wr);
                  }

                wr.setStringAttribute (ID_ATTR, key_id);
                if (friendly_name != null)
                  {
                    wr.setStringAttribute (FRIENDLY_NAME_ATTR, friendly_name);
                  }
                X509Certificate[] certpath = CertificateUtil.getSortedPath (certificates);
                XMLSignatureWrapper.writeX509DataSubset (wr, certpath);

                if (symmetric_key != null)
                  {
                    writeEncryptedKey (wr, certpath[0], key_id);
                  }

                for (PropertyBag property_bag : property_bags.values ())
                  {
                    wr.addChildElement (PROPERTY_BAG_ELEM);
                    wr.setStringAttribute (TYPE_ATTR, property_bag.type);
                    if (property_bag.properties.isEmpty ())
                      {
                        throw new IOException ("Empty " + PROPERTY_BAG_ELEM + ": " + property_bag.type);
                      }
                    for (Property property : property_bag.properties.values ())
                      {
                        wr.addChildElement (PROPERTY_ELEM);
                        wr.setStringAttribute (NAME_ATTR, property.name);
                        wr.setStringAttribute (VALUE_ATTR, property.value);
                        if (property.writable)
                          {
                            wr.setBooleanAttribute (WRITABLE_ATTR, property.writable);
                          }
                        wr.getParent ();
                      }
                    wr.getParent ();
                  }

                for (Logotype logotype : logotypes)
                  {
                    wr.addBinary (LOGO_TYPE_ELEM, logotype.image.getData ());
                    wr.setStringAttribute (MIME_TYPE_ATTR, logotype.image.getMimeType ());
                    wr.setStringAttribute (TYPE_ATTR, logotype.type_uri);
                  }

                if (notify_days_before_expiry > 0)
                  {
                    wr.addChildElement (RENEWAL_SERVICE_ELEM);
                    wr.setIntAttribute (NOTIFY_DAYS_BEFORE_EXPIRY_ATTR, notify_days_before_expiry);
                    if (renewal_urls != null)
                      {
                        for (String s : renewal_urls)
                          {
                            wr.addString (URL_ELEM, s);
                          }
                      }
                    if (renewal_dnss != null)
                      {
                        for (String s : renewal_dnss)
                          {
                            wr.addString (DNS_LOOKUP_ELEM, s);
                          }
                      }
                    wr.getParent ();
                  }

                for (Extension ext : extension_objects)
                  {
                    wr.addBinary (EXTENSION_ELEM, ext.data);
                    wr.setStringAttribute (TYPE_ATTR, ext.type);
                  }

              }


            public void init () throws IOException
              {
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
                return CERTIFIED_PUBLIC_KEY_ELEM;
              }


            protected void fromXML (DOMReaderHelper helper) throws IOException
              {
                throw new IOException ("Should have been implemented in derived class");
              }

          }

      }


    String client_session_id;

    String server_session_id;

    Date server_time;

    String submit_url;

    private String prefix;  // Default: no prefix

    private Vector<CertifiedPublicKey> certified_keys = new Vector<CertifiedPublicKey> ();

    ServerCookie server_cookie;

    boolean xml_enc;

    KeyOperationRequestEncoder key_op_req_enc;

    PresetValueSecurity preset_value_security;

    Vector<KeyOperationRequestEncoder.PresetValue> preset_values;

    boolean output_encryption_certificate;

    byte[] session_hash;


    // Constructors

    @SuppressWarnings("unused")
    private CredentialDeploymentRequestEncoder () {}


    public CredentialDeploymentRequestEncoder (String submit_url,
                                               Date server_time,
                                               PresetValueSecurity preset_value_security,
                                               KeyOperationRequestEncoder key_op_req_enc) throws IOException
      {
        this.submit_url = submit_url;
        this.server_time = server_time;
        this.client_session_id = key_op_req_enc.client_session_id;
        this.server_session_id = key_op_req_enc.server_session_id;
        this.preset_value_security = preset_value_security;
        this.preset_values = key_op_req_enc.preset_values;
        this.session_hash = key_op_req_enc.getSessionHash ();
      }


    public CertifiedPublicKey addCertifiedPublicKey (String key_id, X509Certificate[] certificates)
      {
        CertifiedPublicKey certified_key = new CertifiedPublicKey (key_id, certificates);
        certified_keys.add (certified_key);
        return certified_key;
      }


    public CertifiedPublicKey addCertifiedPublicKey (String key_id, X509Certificate certificate)
      {
        return addCertifiedPublicKey (key_id, new X509Certificate[] {certificate});
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void setOutputEncryptionCertificate (boolean flag)
      {
        output_encryption_certificate = flag;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    private void beginKeyInfo (DOMWriterHelper wr) throws IOException
      {
        wr.pushPrefix (XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
        wr.addChildElementNS (XMLSignatureWrapper.XML_DSIG_NS, XMLSignatureWrapper.KEY_INFO_ELEM);
      }


    private void endKeyInfo (DOMWriterHelper wr) throws IOException
      {
        wr.getParent ();
        wr.popPrefix ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, client_session_id);

        wr.setStringAttribute (ID_ATTR, server_session_id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (xml_enc || !preset_values.isEmpty ())
          {
            XMLEncUtil.addXMLEncNS (wr);
          }

        if (certified_keys.isEmpty ())
          {
            throw new IOException ("Empty request not allowed!");
          }

        ////////////////////////////////////////////////////////////////////////
        // Write [1..n] Credentials
        ////////////////////////////////////////////////////////////////////////
        for (CertifiedPublicKey certified_key : certified_keys)
          {
            wr.addWrapped (certified_key.setupForWrite ());
          }

        ////////////////////////////////////////////////////////////////////////
        // Write optional preset values
        ////////////////////////////////////////////////////////////////////////
        if (!preset_values.isEmpty ())
          {
            if (preset_value_security == null)
              {
                throw new IOException ("Missing encryption public_key!  See constructor.");
              }
            byte[] encrypted_encoder_key = null;
            Mac preset_value_mac = null;
            try
              {
                byte[] encoder_key_value = new byte[preset_value_security.encryption_algorithm == SymEncryptionAlgorithms.AES128_CBC ? 16 : 32];
                SecureRandom.getInstance ("SHA1PRNG").nextBytes (encoder_key_value);
                SecretKeySpec encoder_key = new SecretKeySpec (encoder_key_value, "AES");
                Cipher kek = Cipher.getInstance (preset_value_security.key_wrap_algorithm.getJCEName ());
                kek.init (Cipher.ENCRYPT_MODE, preset_value_security.encryption_certificate.getPublicKey ());
                encrypted_encoder_key = kek.doFinal (encoder_key_value);
                preset_value_mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                preset_value_mac.init (new SecretKeySpec (session_hash, "RAW"));
                preset_value_mac.update (encoder_key_value);

                for (KeyOperationRequestEncoder.PresetValue ps : preset_values)
                  {
                    byte[] iv = new byte[16];
                    SecureRandom.getInstance ("SHA1PRNG").nextBytes (iv);
                    Cipher crypt = Cipher.getInstance (preset_value_security.encryption_algorithm.getJCEName ());
                    crypt.init (Cipher.ENCRYPT_MODE, encoder_key, new IvParameterSpec (iv));
                    ps.encrypted_value = ArrayUtil.add (iv, crypt.doFinal (ps.value.getBytes ("UTF-8")));
                    preset_value_mac.update (ps.encrypted_value);
                  }
              }
            catch (GeneralSecurityException gse)
              {
                throw new IOException (gse.getMessage ());
              }
            wr.addChildElement (PRESET_VALUES_ELEM);
            wr.setBinaryAttribute (MAC_ATTR, preset_value_mac.doFinal ());

            wr.pushPrefix (XML_ENC_NS_PREFIX);

            wr.addChildElementNS (XML_ENC_NS, ENCRYPTED_KEY_ELEM);

            XMLEncUtil.setEncryptionMethod (wr, preset_value_security.key_wrap_algorithm);

            if (output_encryption_certificate)
              {
                beginKeyInfo (wr);
                XMLSignatureWrapper.writeX509DataSubset (wr, new X509Certificate[]{preset_value_security.encryption_certificate});
                endKeyInfo (wr);
              }

            XMLEncUtil.setCipherData (wr, encrypted_encoder_key);

            wr.addString (CARRIED_KEY_NAME_ELEM, PRESET_VALUE_KEY_NAME);

            wr.getParent ();

            for (KeyOperationRequestEncoder.PresetValue ps : preset_values)
              {
                wr.addChildElementNS (XML_ENC_NS, ENCRYPTED_DATA_ELEM);
                wr.setStringAttribute (XMLSignatureWrapper.ID_ATTR, ps.name);

                XMLEncUtil.setEncryptionMethod (wr, preset_value_security.encryption_algorithm);

                beginKeyInfo (wr);
                wr.addString (XMLSignatureWrapper.KEY_NAME_ELEM, PRESET_VALUE_KEY_NAME);
                endKeyInfo (wr);
 
                XMLEncUtil.setCipherData (wr, ps.encrypted_value);

                wr.getParent ();
              }

            wr.popPrefix ();
            wr.getParent ();
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
