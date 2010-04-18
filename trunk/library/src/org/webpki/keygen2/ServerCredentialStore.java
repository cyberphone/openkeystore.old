package org.webpki.keygen2;

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Vector;

import org.webpki.crypto.ECDomains;
import org.webpki.util.ArrayUtil;
import org.webpki.util.MimeTypedObject;
import org.webpki.xml.DOMWriterHelper;

public class ServerCredentialStore implements Serializable
  {
    private static final long serialVersionUID = 1L;
    
    public abstract class ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String type;
        
        public String getType ()
          {
            return type;
          }
        
        public abstract byte getBaseType ();
        
        public byte[] getQualifier () throws IOException
          {
            return new byte[0];
          }
        
        public abstract byte[] getExtensionData () throws IOException;
        
        abstract void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException;
        
        void writeCore (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            wr.setBinaryAttribute (MAC_ATTR, mac_data);
            wr.setStringAttribute (TYPE_ATTR, type);
           
          }
        
        ExtensionInterface (String type)
          {
            this.type = type;
          }
      }

    public class Extension extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] data;

        Extension (String type, byte[] data)
          {
            super (type);
            this.data = data;
          }

        public byte getBaseType ()
          {
            return (byte)0x00;
          }

        public byte[] getExtensionData () throws IOException
          {
            return data;
          }

        void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            wr.addBinary (EXTENSION_ELEM, data);
            writeCore (wr, mac_data);
          }
      }

    public class EncryptedExtension extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] data;

        EncryptedExtension (String type, byte[] data)
          {
            super (type);
            this.data = data;
          }

        public byte getBaseType ()
          {
            return (byte) 0x01;
          }

        public byte[] getExtensionData () throws IOException
          {
            return data;
          }

        void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            wr.addBinary (ENCRYPTED_EXTENSION_ELEM, data);
            writeCore (wr, mac_data);
          }
      }

    public class Logotype extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        MimeTypedObject logotype;

        Logotype (String type, MimeTypedObject logotype)
          {
            super (type);
            this.logotype = logotype;
          }

        public byte getBaseType ()
          {
            return (byte) 0x03;
          }

        public byte[] getExtensionData () throws IOException
          {
            return logotype.getData ();
          }

        public byte[] getQualifier () throws IOException
          {
            return logotype.getMimeType ().getBytes ("UTF-8");
          }

        void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            wr.addBinary (LOGOTYPE_ELEM, logotype.getData ());
            writeCore (wr, mac_data);
            wr.setStringAttribute (MIME_TYPE_ATTR, logotype.getMimeType ());
          }
      }

    public class Property implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String name;

        String value;

        boolean writable;
        
        private Property () {}
      }

    public class PropertyBag extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        LinkedHashMap<String,Property> properties = new LinkedHashMap<String,Property> ();

        public PropertyBag addProperty (String name, String value, boolean writable) throws IOException
          {
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

        PropertyBag (String type)
          {
            super (type);
          }
        
        public byte getBaseType ()
          {
            return (byte)0x02;
          }
        
        private byte[] stringToByteArray (String string) throws IOException
          {
            byte[] raw = string.getBytes ("UTF-8");
            return ArrayUtil.add (new byte[]{(byte)(raw.length >>> 8), (byte)(raw.length & 0xFF)}, raw);
          }
        
        public byte[] getExtensionData () throws IOException
          {
            byte[] data = new byte[0];
            for (Property prop : properties.values ())
              {
                data = ArrayUtil.add (data, 
                                      ArrayUtil.add (stringToByteArray (prop.name),
                                                     ArrayUtil.add (new byte[]{(byte)(prop.writable ? 0x01 : 0x00)} , stringToByteArray (prop.value))));
              }
            return data;
          }

        void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            if (properties.isEmpty ())
              {
                throw new IOException ("Empty " + PROPERTY_BAG_ELEM + ": " + type);
              }
            wr.addChildElement (PROPERTY_BAG_ELEM);
            writeCore (wr, mac_data);
            for (Property property : properties.values ())
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
          }

      }


    class PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;
        
        byte[] encrypted_value;

        PresetValue (byte[] encrypted_value) throws IOException
          {
            this.encrypted_value = encrypted_value;
          }

        void write (DOMWriterHelper wr) throws IOException
          {
            wr.setBinaryAttribute (VALUE_ATTR, encrypted_value);
          }
      }


    public class PUKPolicy extends PresetValue implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String id;

        public String getID ()
          {
            return id;
          }

        PassphraseFormats format;

        int retry_limit;

        PUKPolicy (byte[] value, PassphraseFormats format, int retry_limit) throws IOException
          {
            super (value);
            this.id = puk_prefix + ++next_puk_id_suffix;
            this.format = format;
            this.retry_limit = retry_limit;
          }

        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (PUK_POLICY_ELEM);
            super.write (wr);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());
          }
      }

    public class PINPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean written;

        boolean not_first;

        byte[] preset_test;

        // Actual data


        PUKPolicy puk_policy; // Optional
        
        public PUKPolicy getPUKPolicy ()
          {
            return puk_policy;
          }


        PassphraseFormats format;

        int min_length;

        int max_length;

        int retry_limit;

        PINGrouping group; // Optional

        PatternRestrictions[] pattern_restrictions; // Optional

        boolean caching_support; // Optional

        InputMethods input_method; // Optional


        String id;
        
        public String getID ()
          {
            return id;
          }


        private PINPolicy ()
          {
            this.id = pin_prefix + ++next_pin_id_suffix;
          }

        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (PIN_POLICY_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (MAX_LENGTH_ATTR, max_length);
            wr.setIntAttribute (MIN_LENGTH_ATTR, min_length);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            if (group != null)
              {
                wr.setStringAttribute (GROUPING_ATTR, group.getXMLName ());
              }
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());
            if (pattern_restrictions != null)
              {
                Vector<String> prs = new Vector<String> ();
                for (PatternRestrictions pr : pattern_restrictions)
                  {
                    prs.add (pr.getXMLName ());
                  }
                wr.setListAttribute (PATTERN_RESTRICTIONS_ATTR, prs.toArray (new String[0]));
              }
            if (caching_support)
              {
                wr.setBooleanAttribute (CACHING_SUPPORT_ATTR, caching_support);
              }
            if (input_method != null)
              {
                wr.setStringAttribute (INPUT_METHOD_ATTR, input_method.getXMLName ());
              }
          }

        public PINPolicy setInputMethod (InputMethods input_method)
          {
            this.input_method = input_method;
            return this;
          }

        public PINPolicy setGrouping (PINGrouping group)
          {
            this.group = group;
            return this;
          }

        public PINPolicy setCachingSupport (boolean flag)
          {
            this.caching_support = flag;
            return this;
          }

        public PINPolicy setPatternRestrictions (PatternRestrictions[] patterns)
          {
            this.pattern_restrictions = patterns;
            return this;
          }

      }

    public static abstract class KeyAlgorithmData implements Serializable
      {
        private static final long serialVersionUID = 1L;

        abstract void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException;

        private KeyAlgorithmData ()
          {
          }

        public static final class EC extends KeyAlgorithmData implements Serializable
          {
            private static final long serialVersionUID = 1L;

            ECDomains named_curve;

            @SuppressWarnings("unused")
            private EC ()
              {
              }

            public EC (ECDomains named_curve)
              {
                this.named_curve = named_curve;
              }

            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                wr.addChildElement (EC_ELEM);
                wr.setStringAttribute (NAMED_CURVE_ATTR, named_curve.getURI ());
                wr.getParent ();
              }
          }

        public static final class RSA extends KeyAlgorithmData implements Serializable
          {
            private static final long serialVersionUID = 1L;

            int key_size;

            BigInteger fixed_exponent;

            @SuppressWarnings("unused")
            private RSA ()
              {
              }

            public RSA (int key_size)
              {
                this.key_size = key_size;
              }

            public RSA (int key_size, BigInteger fixed_exponent)
              {
                this (key_size);
                this.fixed_exponent = fixed_exponent;
              }

            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                wr.addChildElement (RSA_ELEM);
                wr.setIntAttribute (KEY_SIZE_ATTR, key_size);
                if (fixed_exponent != null)
                  {
                    wr.setBinaryAttribute (FIXED_EXPONENT_ATTR, fixed_exponent.toByteArray ());
                  }
                wr.getParent ();
              }
          }

        public static final class DSA extends KeyAlgorithmData implements Serializable
          {
            private static final long serialVersionUID = 1L;

            int key_size;

            @SuppressWarnings("unused")
            private DSA ()
              {
              }

            public DSA (int key_size)
              {
                this.key_size = key_size;
              }

            void writeKeyAlgorithmData (DOMWriterHelper wr) throws IOException
              {
                bad ("DSA not implemented!");
              }
          }

      }

    public class KeyProperties implements Serializable
      {
        private static final long serialVersionUID = 1L;

        LinkedHashMap<String,ExtensionInterface> extensions = new LinkedHashMap<String,ExtensionInterface> ();
        
        private void addExtension (ExtensionInterface ei) throws IOException
          {
            if (extensions.put (ei.type, ei) != null)
              {
                bad ("Duplicate extension:" + ei.type);
              }
          }
       

        public PropertyBag addPropertyBag (String type) throws IOException
          {
            PropertyBag pb = new PropertyBag (type);
            addExtension (pb);
            return pb;
          }

        public KeyProperties addExtension (String type, byte[] data) throws IOException
          {
            addExtension (new Extension (type, data));
            return this;
          }

        public KeyProperties addEncryptedExtension (String type, byte[] data) throws IOException
          {
            addExtension (new EncryptedExtension (type, data));
            return this;
          }

        public KeyProperties addLogotype (String type, MimeTypedObject logotype) throws IOException
          {
            addExtension (new Logotype (type, logotype));
            return this;
          }


        X509Certificate[] certificate_path;
        
        public KeyProperties setCertificatePath (X509Certificate[] certificate_path)
          {
            this.certificate_path = certificate_path;
            return this;
          }
        
        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
          }
        

        byte[] encrypted_symmetric_key;
        
        String[] endorsed_algorithms;

        public KeyProperties setSymmetricKey (byte[] encrypted_symmetric_key, String[] endorsed_algorithms)
          {
            this.encrypted_symmetric_key = encrypted_symmetric_key;
            this.endorsed_algorithms = endorsed_algorithms;
            return this;
          }

        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }

        
        String friendly_name;

        public KeyProperties setFriendlyName (String friendly_name)
          {
            this.friendly_name = friendly_name;
            return this;
          }

        public String getFriendlyName ()
          {
            return friendly_name;
          }

        
        PublicKey public_key;   // Filled in by KeyInitializationRequestDecoder

        public PublicKey getPublicKey ()
          {
            return public_key;
          }


        byte[] key_attestation;   // Filled in by KeyInitializationRequestDecoder
        
        public byte[] getKeyAttestationy ()
          {
            return key_attestation;
          }


        byte[] encrypted_private_key;

        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }
        

        boolean exportable;
        
        public KeyProperties setExportable (boolean flag)
          {
            exportable = flag;
            return this;
          }

        public boolean getExportable ()
          {
            return exportable;
          }


        String id;

        public String getID ()
          {
            return id;
          }
        

        KeyGen2KeyUsage key_usage;

        public KeyGen2KeyUsage getKeyUsage ()
          {
            return key_usage;
          }

        KeyAlgorithmData key_alg_data;

        PINPolicy pin_policy;
        
        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }

        
        PresetValue preset_pin;
        
        public byte[] getEncryptedPIN ()
          {
            return preset_pin == null ? null : preset_pin.encrypted_value;
          }
        

        boolean user_modifiable;
        
        public boolean getUserModifiable ()
          {
            return user_modifiable;
          }


        boolean device_pin_protected;

        public boolean getDevicePINProtected ()
          {
            return device_pin_protected;
          }

        KeyProperties (KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protected) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.key_usage = key_usage;
            this.key_alg_data = key_alg_data;
            this.pin_policy = pin_policy;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;
// TODO
            this.public_key = org.webpki.crypto.test.ECKeys.PUBLIC_KEY1;
            if (pin_policy != null)
              {
                if (pin_policy.not_first)
                  {
                    if (pin_policy.group == PINGrouping.SHARED && ((pin_policy.preset_test == null && preset_pin != null) || (pin_policy.preset_test != null && preset_pin == null)))
                      {
                        bad ("\"shared\" PIN keys must either have no \"preset_pin\" " + "value or all be preset");
                      }
                  }
                else
                  {
                    pin_policy.not_first = true;
                    pin_policy.preset_test = preset_pin == null ? null : preset_pin.encrypted_value;
                  }
              }
            this.user_modifiable = !device_pin_protected;
          }

        void writeRequest (DOMWriterHelper wr) throws IOException
          {
            if (device_pin_protected)
              {
                wr.addChildElement (DEVICE_SYNCHRONIZED_PIN_ELEM);
              }
            if (preset_pin != null)
              {
                wr.addChildElement (PRESET_PIN_ELEM);
                preset_pin.write (wr);
              }
            wr.addChildElement (KEY_PAIR_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setStringAttribute (KEY_USAGE_ATTR, key_usage.getXMLName ());

            if (exportable)
              {
                wr.setBooleanAttribute (EXPORTABLE_ATTR, exportable);
              }

            key_alg_data.writeKeyAlgorithmData (wr);

            wr.getParent ();

            if (device_pin_protected || preset_pin != null)
              {
                wr.getParent ();
              }
          }
      }


    int next_personal_code = 1;

    String key_prefix = "Key.";

    int next_key_id_suffix = 0;

    String pin_prefix = "PIN.";

    int next_pin_id_suffix = 0;

    String puk_prefix = "PUK.";

    int next_puk_id_suffix = 0;

    short mac_sequence_counter;

    LinkedHashMap<String,KeyProperties> requested_keys = new LinkedHashMap<String,KeyProperties> ();
    
    public Collection<KeyProperties> getKeyProperties ()
      {
        return requested_keys.values ();
      }

    String server_session_id;

    String client_session_id;
    
    String issuer_uri;
    
    void checkSession (String client_session_id, String server_session_id) throws IOException
      {
        if (!this.client_session_id.equals (client_session_id) || !this.server_session_id.equals (server_session_id))
          {
            bad ("Session ID mismatch");
          }
      }
    

    // Constructors

    public ServerCredentialStore (String client_session_id, String server_session_id, String issuer_uri) throws IOException
      {
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
        this.issuer_uri = issuer_uri;
      }

    static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }

    public PINPolicy createPINPolicy (PassphraseFormats format, int min_length, int max_length, int retry_limit, PUKPolicy puk_policy) throws IOException
      {
        PINPolicy pin_policy = new PINPolicy ();
        pin_policy.format = format;
        pin_policy.min_length = min_length;
        pin_policy.max_length = max_length;
        pin_policy.retry_limit = retry_limit;
        pin_policy.puk_policy = puk_policy;
        if (format == null)
          {
            bad ("PassphraseFormats must not be null");
          }
        if (min_length > max_length)
          {
            bad ("min_length > max_length");
          }
        return pin_policy;
      }


    public PUKPolicy createPUKPolicy (byte[] encrypted_puk, PassphraseFormats format, int retry_limit) throws IOException
      {
        return new PUKPolicy (encrypted_puk, format, retry_limit);
      }


    private KeyProperties addKeyProperties (KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protected) throws IOException
      {
        KeyProperties rk = new KeyProperties (key_usage, key_alg_data, pin_policy, preset_pin, device_pin_protected);
        requested_keys.put (rk.getID (), rk);
        return rk;
      }


    public KeyProperties createKeyWithPresetPIN (KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, byte[] encrypted_pin, boolean user_modifiable) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        KeyProperties key = addKeyProperties (key_usage, key_alg_data, pin_policy, new PresetValue (encrypted_pin), false);
        key.user_modifiable = user_modifiable;
        return key;
      }


    public KeyProperties createKey (KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy) throws IOException
      {
        return addKeyProperties (key_usage, key_alg_data, pin_policy, null, false);
      }


    public KeyProperties createDevicePINProtectedKey (KeyGen2KeyUsage key_usage, KeyAlgorithmData key_alg_data) throws IOException
      {
        return addKeyProperties (key_usage, key_alg_data, null, null, true);
      }

  }
