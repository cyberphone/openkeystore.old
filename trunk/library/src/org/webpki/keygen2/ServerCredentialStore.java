/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.keygen2;

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
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
    
    static class MacGenerator
      {
        private ByteArrayOutputStream baos;
        
        MacGenerator ()
          {
            baos = new ByteArrayOutputStream ();
          }
        
        private byte[] short2bytes (int s)
          {
            return new byte[]{(byte)(s >>> 8), (byte)s};
          }
  
        private byte[] int2bytes (int i)
          {
            return new byte[]{(byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i};
          }
  
        void addBlob (byte[] data) throws IOException
          {
            baos.write (int2bytes (data.length));
            baos.write (data);
          }

        void addArray (byte[] data) throws IOException
          {
            baos.write(short2bytes (data.length));
            baos.write (data);
          }
        
        void addString (String string) throws IOException
          {
            addArray (string.getBytes ("UTF-8"));
          }
        
        void addInt (int i) throws IOException
          {
            baos.write (int2bytes (i));
          }
        
        void addShort (int s) throws IOException
          {
            baos.write (short2bytes (s));
          }
        
        void addByte (byte b)
          {
            baos.write (b);
          }
        
        void addBool (boolean flag)
          {
            baos.write (flag ? (byte) 0x01 : (byte) 0x00);
          }
        
        byte[] getResult ()
          {
            return baos.toByteArray ();
          }
       
      }
  
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

        byte[] encrypted_data;

        EncryptedExtension (String type, byte[] encrypted_data)
          {
            super (type);
            this.encrypted_data = encrypted_data;
          }

        public byte getBaseType ()
          {
            return (byte) 0x01;
          }

        public byte[] getExtensionData () throws IOException
          {
            return encrypted_data;
          }

        void writeExtension (DOMWriterHelper wr, byte[] mac_data) throws IOException
          {
            wr.addBinary (ENCRYPTED_EXTENSION_ELEM, encrypted_data);
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
        
        public byte[] getExtensionData () throws IOException
          {
            MacGenerator convert = new MacGenerator ();
            for (Property prop : properties.values ())
              {
                convert.addString (prop.name);
                convert.addBool (prop.writable);
                convert.addString (prop.value);
               }
            return convert.getResult ();
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
            wr.getParent ();
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

        void writePolicy (DOMWriterHelper wr, ServerSessionKeyInterface sess_key_interface) throws IOException
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


        boolean user_modifiable;
        
        boolean user_modifiable_set;
        
        public boolean getUserModifiable ()
          {
            return user_modifiable;
          }

        public PINPolicy setUserModifiable (boolean flag)
          {
            user_modifiable = flag;
            user_modifiable_set = true;
            return this;
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

        void writePolicy (DOMWriterHelper wr, ServerSessionKeyInterface sess_key_interface) throws IOException
          {
            wr.addChildElement (PIN_POLICY_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (MAX_LENGTH_ATTR, max_length);
            wr.setIntAttribute (MIN_LENGTH_ATTR, min_length);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            if (user_modifiable_set)
              {
                wr.setBooleanAttribute (USER_MODIFIABLE_ATTR, user_modifiable);
              }
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

        public static final class EC extends KeyAlgorithmData implements Serializable
          {
            private static final long serialVersionUID = 1L;

            ECDomains named_curve;

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

        public KeyProperties addEncryptedExtension (String type, byte[] encrypted_data) throws IOException
          {
            addExtension (new EncryptedExtension (type, encrypted_data));
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
        
        public byte[] getKeyAttestation ()
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
        
        
        byte[] server_seed = CryptoConstants.DEFAULT_SEED;
        boolean server_seed_set;
        
        public KeyProperties setServerSeed (byte[] server_seed)
          {
            server_seed_set = true;
            this.server_seed = server_seed;
            return this;
          }
        
        boolean private_key_backup;
        
        public KeyProperties setPrivateKeyBackup (boolean flag)
          {
            private_key_backup = flag;
            return this;
          }
        
        public boolean getPrivateKeyBackupFlag ()
          {
            return private_key_backup;
          }


        String id;

        public String getID ()
          {
            return id;
          }
        

        KeyUsage key_usage;

        public KeyUsage getKeyUsage ()
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
        

        boolean device_pin_protected;

        public boolean getDevicePINProtected ()
          {
            return device_pin_protected;
          }

        KeyProperties (KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protected) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.key_usage = key_usage;
            this.key_alg_data = key_alg_data;
            this.pin_policy = pin_policy;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;
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
          }

        void writeRequest (DOMWriterHelper wr, ServerSessionKeyInterface sess_key_interface) throws IOException, GeneralSecurityException
          {
            MacGenerator key_pair_mac = new MacGenerator ();
            key_pair_mac.addString (id);
            key_pair_mac.addArray (server_seed);
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
            
            if (private_key_backup)
              {
                wr.setBooleanAttribute (PRIVATE_KEY_BACKUP_ATTR, private_key_backup);
              }
            
            if (server_seed_set)
              {
                if (server_seed.length != 32)
                  {
                    bad ("Sever seed must be 32 bytes");
                  }
                wr.setBinaryAttribute (SERVER_SEED_ATTR, server_seed);
              }

            wr.setBinaryAttribute (MAC_ATTR, mac (key_pair_mac.getResult (), APIDescriptors.CREATE_KEY_PAIR, sess_key_interface));
            
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
    
    private byte[] getMACSequenceCounterAndUpdate ()
      {
        int q = mac_sequence_counter++;
        return  new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
      }

    byte[] mac (byte[] data, APIDescriptors method, ServerSessionKeyInterface sess_key_interface) throws IOException, GeneralSecurityException
      {
        return sess_key_interface.mac (data, ArrayUtil.add (method.getBinary (), getMACSequenceCounterAndUpdate ()));
      }
    
    byte[] attest (byte[] data, ServerSessionKeyInterface sess_key_interface) throws IOException, GeneralSecurityException
      {
        return sess_key_interface.mac (data, CryptoConstants.CRYPTO_STRING_DEVICE_ATTEST); 
      }
    
    void checkFinalResult (byte[] close_session_attestation,  ServerSessionKeyInterface sess_key_interface) throws IOException, GeneralSecurityException
      {
  
        if (!ArrayUtil.compare (attest (ArrayUtil.add (CryptoConstants.CRYPTO_STRING_SUCCESS, 
                                                       getMACSequenceCounterAndUpdate ()),
                                        sess_key_interface),
                                close_session_attestation))
          {
            bad ("Final attestation failed!");
          }
      }
  
    static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }
    
 
    // Constructor

    public ServerCredentialStore (ProvisioningSessionResponseDecoder prov_sess_response,
                                  ProvisioningSessionRequestEncoder prov_sess_request) throws IOException
      {
        this.client_session_id = prov_sess_response.client_session_id;
        this.server_session_id = prov_sess_request.server_session_id;
        this.issuer_uri = prov_sess_request.submit_url;
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


    private KeyProperties addKeyProperties (KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protected) throws IOException
      {
        KeyProperties key = new KeyProperties (key_usage, key_alg_data, pin_policy, preset_pin, device_pin_protected);
        requested_keys.put (key.getID (), key);
        return key;
      }


    public KeyProperties createKeyWithPresetPIN (KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy, byte[] encrypted_pin) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        return addKeyProperties (key_usage, key_alg_data, pin_policy, new PresetValue (encrypted_pin), false);
      }


    public KeyProperties createKey (KeyUsage key_usage, KeyAlgorithmData key_alg_data, PINPolicy pin_policy) throws IOException
      {
        KeyProperties key = addKeyProperties (key_usage, key_alg_data, pin_policy, null, false);
        if (pin_policy != null)
          {
            pin_policy.user_modifiable = true;
          }
        return key;
      }


    public KeyProperties createDevicePINProtectedKey (KeyUsage key_usage, KeyAlgorithmData key_alg_data) throws IOException
      {
        return addKeyProperties (key_usage, key_alg_data, null, null, true);
      }

  }
