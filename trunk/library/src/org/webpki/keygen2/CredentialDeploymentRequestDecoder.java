package org.webpki.keygen2;

import java.io.IOException;

import org.w3c.dom.Element;

import java.util.Vector;
import java.util.LinkedHashMap;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.webpki.util.ImageData;
import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.EncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class CredentialDeploymentRequestDecoder extends CredentialDeploymentRequest
  {

    public class PresetValue
      {
        boolean hidden;

        byte[] encrypted_value;

        String value;

        boolean is_puk;

        Object local_reference_object;


        public boolean isHidden ()
          {
            return hidden;
          }


        public boolean isPUK ()
          {
            return is_puk;
          }


        public Object getLocalReferenceObject ()
          {
            return local_reference_object;
          }


        public String getValue () throws IOException
          {
            if (value == null)
              {
                try
                  {
                    if (encoder_key == null)
                      {
                        if (encrypted_encoder_key == null)
                          {
                            bad ("Missing in XML object: " + PRESET_VALUES_ELEM);
                          }
                        if (master_key_decrypter == null)
                          {
                            bad ("You must call \"setDecrypter\" before accessing data");
                          }
                        encoder_key = master_key_decrypter.decrypt (encrypted_encoder_key, encryption_certificate);
                        Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
/*
                        mac.init (new SecretKeySpec (key_operation_request_decoder.getSessionHash (), "RAW"));
*/
                        mac.update (encoder_key);
                        for (byte[] enc_val : encrypted_preset_values.values ())
                          {
                            mac.update (enc_val);
                          }
                        if (!ArrayUtil.compare (mac_key, mac.doFinal ()))
                          {
                            bad ("MAC error");
                          }
                      }
                    if (encrypted_value.length < 32 || encrypted_value.length % 16 != 0)
                      {
                        bad ("Unexpected length of encrypted data: " + encrypted_value.length);
                      }
                    Cipher crypt = Cipher.getInstance (SymEncryptionAlgorithms.AES_CBC_P5.getJCEName ());
                    crypt.init (Cipher.DECRYPT_MODE,
                                new SecretKeySpec (encoder_key, "AES"),
                                new IvParameterSpec (encrypted_value, 0, 16));
                    value = new String (crypt.doFinal (encrypted_value, 16, encrypted_value.length - 16), "UTF-8");
                  }
                catch (GeneralSecurityException gse)
                  {
                    bad (gse.getMessage ());
                  }
              }
            return value;
          }

      }


    public class Extension
      {
        private Extension () {}

        String type;

        byte[] data;


        public byte[] getData ()
          {
            return data;
          }


        public String getType ()
          {
            return type;
          }

      }


    public class Property
      {
        private Property () {}

        String name;

        String value;

        boolean writable;


        public boolean isWritable ()
          {
            return writable;
          }


        public String getName ()
          {
            return name;
          }


        public String getValue ()
          {
            return value;
          }
      }


    public class PropertyBag
      {
        private PropertyBag () {}

        String type;

        Vector<Property> properties = new Vector<Property> ();


        public Property[] getProperties ()
          {
            return properties.toArray (new Property[0]);
          }


        public String getType ()
          {
            return type;
          }
      }


    @SuppressWarnings("serial")
    public class Logotype extends ImageData
      {
        String type_uri;

        Logotype (byte[] data, String mime_type, String type_uri)
          {
            super (data, mime_type);
            this.type_uri = type_uri;
          }

        public String getType ()
          {
            return type_uri;
          }
      }


    public class CertifiedPublicKey
      {
        X509Certificate[] certificate_path;

        String id;

        String friendly_name;

        RenewalService renewal_service;

        Vector<PropertyBag> property_bags = new Vector<PropertyBag> ();

        byte[] encrypted_symmetric_key;

        byte[] mac;

        String[] endorsed_algorithms;

        String piggyback_mac_algorithm;

        Vector<Logotype> logotypes = new Vector<Logotype> ();

        Vector<Extension> extension_objects = new Vector<Extension> ();

        XMLSignatureWrapper cpk_signature;

        CertifiedPublicKey () { }


        CertifiedPublicKey (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            Element root = rd.getNext (CERTIFIED_PUBLIC_KEY_ELEM);
            id = ah.getString (ID_ATTR);
            friendly_name = ah.getStringConditional (FRIENDLY_NAME_ATTR, null);
            rd.getChild ();

            certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);

            if (rd.hasNext (SYMMETRIC_KEY_ELEM))
              {
                rd.getNext (SYMMETRIC_KEY_ELEM);
                mac = ah.getBinary (MAC_ATTR);
                endorsed_algorithms = getSortedAlgorithms (ah.getList (ENDORSED_ALGORITHMS_ATTR));
/*
                piggyback_mac_algorithm = ah.getStringConditional (MAC_ALGORITHM_ATTR,
                                                                   KeyGen2URIs.ALGORITHMS.MAC_PIGGYBACK_1);
*/
 
                rd.getChild ();
/*
                rd.getNext (ENCRYPTED_KEY_ELEM);
                rd.getChild ();

                XMLEncUtil.getEncryptionMethod (rd, new EncryptionAlgorithms[]{AsymEncryptionAlgorithms.RSA_PKCS_1});

                encrypted_symmetric_key = XMLEncUtil.getCipherValue (rd);
*/
                rd.getParent ();

                rd.getParent ();
              }

            while (rd.hasNext (PROPERTY_BAG_ELEM))
              {
                rd.getNext (PROPERTY_BAG_ELEM);
                PropertyBag property_bag = new PropertyBag ();
                property_bag.type = ah.getString (TYPE_ATTR);
                rd.getChild ();
                while (rd.hasNext (PROPERTY_ELEM))
                  {
                    rd.getNext (PROPERTY_ELEM);
                    Property property = new Property ();
                    property.name = ah.getString (NAME_ATTR);
                    property.value = ah.getString (VALUE_ATTR);
                    property.writable = ah.getBooleanConditional (WRITABLE_ATTR);
                    property_bag.properties.add (property);
                  }
                property_bags.add (property_bag);
                rd.getParent ();
              }

            while (rd.hasNext (LOGO_TYPE_ELEM))
              {
                logotypes.add (new Logotype (rd.getBinary (LOGO_TYPE_ELEM),
                                             ah.getString (MIME_TYPE_ATTR),
                                             ah.getString (TYPE_ATTR)));
              }

            if (rd.hasNext (RENEWAL_SERVICE_ELEM))
              {
                rd.getNext (RENEWAL_SERVICE_ELEM);
                renewal_service = new RenewalService ();
                renewal_service.notify_days_before_expiry = ah.getInt (NOTIFY_DAYS_BEFORE_EXPIRY_ATTR);
                Vector<String> renewal_urls = new Vector<String> ();
                Vector<String> renewal_dnss = new Vector<String> ();
                rd.getChild ();
                do
                  {
                    if (rd.hasNext (URL_ELEM))
                      {
                        renewal_urls.add (rd.getString (URL_ELEM));
                      }
                    else
                      {
                        renewal_dnss.add (rd.getString (DNS_LOOKUP_ELEM));
                      }
                  }
                while (rd.hasNext ());
                rd.getParent ();
                renewal_service.renewal_urls = renewal_urls.toArray (new String[0]);
                renewal_service.renewal_dnss = renewal_dnss.toArray (new String[0]);
              }

            while (rd.hasNext (EXTENSION_ELEM))
              {
                Extension ext = new Extension ();
                ext.data = rd.getBinary (EXTENSION_ELEM);
                ext.type = ah.getString (TYPE_ATTR);
                extension_objects.add (ext);
              }

            if (rd.hasNext ())
              {
                cpk_signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
                JKSCAVerifier verifier = new JKSCAVerifier ();
                new XMLVerifier (verifier).validateEnvelopedSignature (null, root, cpk_signature, id);
                CredentialDeploymentRequest.checkCertificateOrder (certificate_path,
                                                                   verifier.getSignerCertificatePath ());
              }

            rd.getParent ();
          }


        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
          }


        public byte[] getSymmetricKey (SymmetricKeyDecrypter symmetric_key_decrypter) throws IOException
          {
            if (encrypted_symmetric_key == null)
              {
                throw new IOException ("No symmetric key available");
              }
            byte[] symmetric_key = null;
            try
              {
                symmetric_key = symmetric_key_decrypter.decrypt (encrypted_symmetric_key, certificate_path[0]);
/*
                if (!ArrayUtil.compare (mac, getAlgorithmsMac (symmetric_key, id, client_session_id, server_session_id, endorsed_algorithms)))
                  {
                    throw new IOException ("Symmetric key MAC error");
                  }
*/
              }
            catch (GeneralSecurityException gse)
              {
                throw new IOException (gse.getMessage ());
              }
            return symmetric_key;
          }


        public boolean hasSymmetricKey ()
          {
            return encrypted_symmetric_key != null;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        public byte[] getSymmetricKeyMac ()
          {
            return mac;
          }


        public String[] getSymmetricKeyEndorsedAlgorithms ()
          {
            return endorsed_algorithms;
          }


        public String getPiggybackMACAlgorithm ()
          {
            return piggyback_mac_algorithm;
          }


        public boolean isSigned ()
          {
            return cpk_signature != null;
          }


        public String getID ()
          {
            return id;
          }


        public String getFriendlyName ()
          {
            return friendly_name;
          }


        public RenewalService getRenewalService ()
          {
            return renewal_service;
          }


        public PropertyBag[] getPropertyBags ()
          {
            return property_bags.toArray (new PropertyBag[0]);
          }


        public Logotype[] getLogotypes ()
          {
            return logotypes.toArray (new Logotype[0]);
          }


        public Extension[] getExtensions ()
          {
            return extension_objects.toArray (new Extension[0]);
          }

      }
    

    public class RenewalService
      {
        int notify_days_before_expiry;

        String[] renewal_urls;

        String[] renewal_dnss;

        private RenewalService () {}


        public int getNotifyDaysBeforeExpiry ()
          {
            return notify_days_before_expiry;
          }


        public String[] getURLs ()
          {
            return renewal_urls;
          }


        public String[] getDNSLookups ()
          {
            return renewal_dnss;
          }
      }


    private void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    private Vector<CertifiedPublicKey> certified_keys = new Vector<CertifiedPublicKey> ();
      
    private String client_session_id;

    private String server_session_id;

    private String server_time;

    private String submit_url;

    private ServerCookie server_cookie;                     // Optional

    private XMLSignatureWrapper signature;                  // Optional

    private X509Certificate encryption_certificate;         // Optional

    private byte[] encrypted_encoder_key;

    private byte[] mac_key;

    private byte[] encoder_key;

    private SymmetricKeyDecrypter master_key_decrypter;

    private LinkedHashMap<String,byte[]> encrypted_preset_values = new LinkedHashMap<String,byte[]> ();

    private Vector<PresetValue> preset_values = new Vector<PresetValue> ();

    private KeyInitializationRequestDecoder key_operation_request_decoder;


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public CertifiedPublicKey[] getCertifiedPublicKeys ()
      {
        return certified_keys.toArray (new CertifiedPublicKey[0]);
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public void setDecrypter (SymmetricKeyDecrypter master_key_decrypter)
      {
        this.master_key_decrypter = master_key_decrypter;
      }


    public void setKeyOperationRequestDecoder (KeyInitializationRequestDecoder key_operation_request_decoder)
      {
        this.key_operation_request_decoder = key_operation_request_decoder;
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public PresetValue[] getPresetValues () throws IOException
      {
        if (key_operation_request_decoder == null)
          {
            bad ("You must call \"setKeyOperationRequestDecoder\" first");
          }
/*
        for (KeyInitializationRequestDecoder.PresetValueReference pvr : key_operation_request_decoder.preset_value_references)
          {
            PresetValue pv = new PresetValue ();
            if ((pv.encrypted_value = encrypted_preset_values.get (pvr.data)) == null)
              {
                bad ("Missing data for: " + pvr.data);
              }

            pv.is_puk = pvr instanceof KeyInitializationRequestDecoder.PUKPolicy;
            pv.local_reference_object = pvr.local_reference_object;
            pv.hidden = pvr.hidden;
            preset_values.add (pv);
          }
*/
        return preset_values.toArray (new PresetValue[0]);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        server_session_id = ah.getString (ID_ATTR);

        server_time = ah.getString (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certified_keys [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do 
          {
            certified_keys.add (new CertifiedPublicKey (rd));
          }
        while (rd.hasNext (CERTIFIED_PUBLIC_KEY_ELEM));

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional preset values
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (PRESET_VALUES_ELEM))
          {
            rd.getNext (PRESET_VALUES_ELEM);
            mac_key = ah.getBinary (MAC_ATTR);
            rd.getChild ();

/*
            rd.getNext (ENCRYPTED_KEY_ELEM);
            rd.getChild ();
            XMLEncUtil.getEncryptionMethod (rd, new EncryptionAlgorithms[]{AsymEncryptionAlgorithms.RSA_PKCS_1});

            if (rd.hasNext (XMLSignatureWrapper.KEY_INFO_ELEM))
              {
                rd.getNext (XMLSignatureWrapper.KEY_INFO_ELEM);
                rd.getChild ();
                encryption_certificate = XMLSignatureWrapper.readSortedX509DataSubset (rd)[0];
                rd.getParent ();
              }
            encrypted_encoder_key = XMLEncUtil.getCipherValue (rd);
            String carried_key_name = rd.getString (CARRIED_KEY_NAME_ELEM);
            rd.getParent ();

            EncryptionAlgorithms[] granted = new EncryptionAlgorithms[]{SymEncryptionAlgorithms.AES128_CBC,
                                                                        SymEncryptionAlgorithms.AES256_CBC};

            while (rd.hasNext (ENCRYPTED_DATA_ELEM))
              {
                rd.getNext (ENCRYPTED_DATA_ELEM);
                String id = ah.getString (XMLSignatureWrapper.ID_ATTR);
                rd.getChild ();

                granted = new EncryptionAlgorithms[]{XMLEncUtil.getEncryptionMethod (rd, granted)};

                rd.getNext (XMLSignatureWrapper.KEY_INFO_ELEM);
                rd.getChild ();
                String key_name = rd.getString (XMLSignatureWrapper.KEY_NAME_ELEM);
                if (!carried_key_name.equals (key_name))
                  {
                    bad ("Unexpected symmetric key name: " + key_name);
                  }
                rd.getParent ();
                encrypted_preset_values.put (id, XMLEncUtil.getCipherValue (rd));
                rd.getParent ();
              }
            rd.getParent ();
*/
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }
