/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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

import java.io.IOException;
import java.io.Serializable;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.Vector;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.SecureKeyStore;
import org.webpki.util.ArrayUtil;
import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMWriterHelper;

public class ServerCredentialStore implements Serializable
  {
    private static final long serialVersionUID = 1L;
    
    enum PostOperation
      {
        DELETE_KEY            (SecureKeyStore.METHOD_PP_DELETE_KEY,           DELETE_KEY_ELEM), 
        UNLOCK_KEY            (SecureKeyStore.METHOD_PP_UNLOCK_KEY,           UNLOCK_KEY_ELEM), 
        UPDATE_KEY            (SecureKeyStore.METHOD_PP_UPDATE_KEY,           UPDATE_KEY_ELEM), 
        CLONE_KEY_PROTECTION  (SecureKeyStore.METHOD_PP_CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_ELEM);
        
        private byte[] method;
        
        private String xml_elem;
        
        PostOperation (byte[] method, String xml_elem)
          {
            this.method = method;
            this.xml_elem = xml_elem;
          }

        byte[] getMethod ()
          {
            return method;
          }
        
        String getXMLElem ()
          {
            return xml_elem;
          }
      }
    
    class PostProvisioningTargetKey implements Serializable
      {
        private static final long serialVersionUID = 1L;
        
        String client_session_id;
        
        String server_session_id;
        
        PublicKey key_management_key;
      
        byte[] certificate_data;
        
        PostOperation post_operation;
        
        PostProvisioningTargetKey (String client_session_id,
                                   String server_session_id,
                                   byte[] certificate_data,
                                   PublicKey key_management_key,
                                   PostOperation post_operation)
          {
            this.client_session_id = client_session_id;
            this.server_session_id = server_session_id;
            this.certificate_data = certificate_data;
            this.key_management_key = key_management_key;
            this.post_operation = post_operation;
          }
  
        public boolean equals (Object o)
          {
            return o instanceof PostProvisioningTargetKey && 
                   client_session_id.equals(((PostProvisioningTargetKey)o).client_session_id) &&
                   server_session_id.equals (((PostProvisioningTargetKey)o).server_session_id) &&
                   ArrayUtil.compare (certificate_data, ((PostProvisioningTargetKey)o).certificate_data);
          }
      }
  
    Vector<PostProvisioningTargetKey> post_operations = new Vector<PostProvisioningTargetKey> ();
  
    public abstract class ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String type;
        
        public String getType ()
          {
            return type;
          }
        
        public abstract byte getSubType ();
        
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

        public byte getSubType ()
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

        public byte getSubType ()
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

        public byte getSubType ()
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
        
        public String getName ()
          {
            return name;
          }
        
        public String getValue ()
          {
            return value;
          }
        
        public boolean isWritable ()
          {
            return writable;
          }
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
        
        public byte getSubType ()
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
        
        public Property[] getProperties ()
          {
            return properties.values ().toArray (new Property[0]);
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

        PassphraseFormat format;

        int retry_limit;

        PUKPolicy (byte[] value, PassphraseFormat format, int retry_limit) throws IOException
          {
            super (value);
            this.id = puk_prefix + ++next_puk_id_suffix;
            this.format = format;
            this.retry_limit = retry_limit;
          }

        void writePolicy (DOMWriterHelper wr, ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
          {
            wr.addChildElement (PUK_POLICY_ELEM);
            super.write (wr);

            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retry_limit);
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());

            MacGenerator puk_policy_mac = new MacGenerator ();
            puk_policy_mac.addString (id);
            puk_policy_mac.addArray (encrypted_value);
            puk_policy_mac.addByte (format.getSKSValue ());
            puk_policy_mac.addShort (retry_limit);
            wr.setBinaryAttribute (MAC_ATTR, mac (puk_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PUK_POLICY, server_crypto_interface));
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
        
        boolean user_defined;
        
        public boolean getUserDefinedFlag ()
          {
            return user_defined;
          }


        PassphraseFormat format;

        int min_length;

        int max_length;

        int retry_limit;

        Grouping grouping; // Optional

        Set<PatternRestriction> pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);

        InputMethod input_method; // Optional


        String id;
        
        public String getID ()
          {
            return id;
          }


        private PINPolicy ()
          {
            this.id = pin_prefix + ++next_pin_id_suffix;
          }

        void writePolicy (DOMWriterHelper wr, ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
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
            if (grouping != null)
              {
                wr.setStringAttribute (GROUPING_ATTR, grouping.getXMLName ());
              }
            wr.setStringAttribute (FORMAT_ATTR, format.getXMLName ());
            if (!pattern_restrictions.isEmpty ())
              {
                Vector<String> prs = new Vector<String> ();
                for (PatternRestriction pr : pattern_restrictions)
                  {
                    prs.add (pr.getXMLName ());
                  }
                wr.setListAttribute (PATTERN_RESTRICTIONS_ATTR, prs.toArray (new String[0]));
              }
            if (input_method != null)
              {
                wr.setStringAttribute (INPUT_METHOD_ATTR, input_method.getXMLName ());
              }

            MacGenerator pin_policy_mac = new MacGenerator ();
            pin_policy_mac.addString (id);
            pin_policy_mac.addString (puk_policy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : puk_policy.id);
            pin_policy_mac.addBool (user_defined);
            pin_policy_mac.addBool (user_modifiable);
            pin_policy_mac.addByte (format.getSKSValue ());
            pin_policy_mac.addShort (retry_limit);
            pin_policy_mac.addByte (grouping == null ? Grouping.NONE.getSKSValue () : grouping.getSKSValue ());
            pin_policy_mac.addByte (PatternRestriction.getSKSValue (pattern_restrictions));
            pin_policy_mac.addShort (min_length);
            pin_policy_mac.addShort (max_length);
            pin_policy_mac.addByte (input_method == null ? InputMethod.ANY.getSKSValue () : input_method.getSKSValue ());
            wr.setBinaryAttribute (MAC_ATTR, mac (pin_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PIN_POLICY, server_crypto_interface));
          }

        public PINPolicy setInputMethod (InputMethod input_method)
          {
            this.input_method = input_method;
            return this;
          }

        public PINPolicy setGrouping (Grouping grouping)
          {
            this.grouping = grouping;
            return this;
          }

        public PINPolicy addPatternRestriction (PatternRestriction pattern)
          {
            this.pattern_restrictions.add (pattern);
            return this;
          }
      }


    public class KeyProperties implements Serializable
      {
        private static final long serialVersionUID = 1L;

        LinkedHashMap<String,ExtensionInterface> extensions = new LinkedHashMap<String,ExtensionInterface> ();
        
        PostProvisioningTargetKey clone_or_update_operation;
        
        boolean key_init_done;
        
        byte[] expected_attest_mac_count;  // Two bytes
        
        private void addExtension (ExtensionInterface ei) throws IOException
          {
            if (extensions.put (ei.type, ei) != null)
              {
                bad ("Duplicate extension:" + ei.type);
              }
          }
        
        public PropertyBag[] getPropertyBags ()
          {
            Vector<PropertyBag> prop_bags = new Vector<PropertyBag> ();
            for (ExtensionInterface ei : extensions.values ())
              {
                if (ei instanceof PropertyBag)
                  {
                    prop_bags.add ((PropertyBag) ei);
                  }
              }
            return prop_bags.toArray (new PropertyBag[0]);
          }
        
        public PropertyBag addPropertyBag (String type) throws IOException
          {
            PropertyBag pb = new PropertyBag (type);
            addExtension (pb);
            return pb;
          }


        Object object;
        
        public KeyProperties setUserObject (Object object)
          {
            this.object = object;
            return this;
          }
        
        public Object getUserObject ()
          {
            return object;
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
        
        public KeyProperties setEncryptedSymmetricKey (byte[] encrypted_symmetric_key) throws IOException
          {
            this.encrypted_symmetric_key = encrypted_symmetric_key;
            return this;
          }
        

        String[] endorsed_algorithms;

        public KeyProperties setEndorsedAlgorithms (String[] endorsed_algorithms) throws IOException
          {
            this.endorsed_algorithms = BasicCapabilities.getSortedAlgorithms (endorsed_algorithms);
            return this;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        byte[] encrypted_private_key;
        
        public KeyProperties setEncryptedPrivateKey (byte[] encrypted_private_key)
          {
            this.encrypted_private_key = encrypted_private_key;
            return this;
          }

        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
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

        
        PublicKey public_key;   // Filled in by KeyCreationRequestDecoder

        public PublicKey getPublicKey ()
          {
            return public_key;
          }


        byte[] attestation;   // Filled in by KeyCreationRequestDecoder
        
        public byte[] getAttestation ()
          {
            return attestation;
          }


        ExportProtection export_protection;
        
        public KeyProperties setExportProtection (ExportProtection export_protection)
          {
            this.export_protection = export_protection;
            return this;
          }

        public ExportProtection getExportPolicy ()
          {
            return export_protection;
          }
        
        
        byte[] server_seed;
        
        public KeyProperties setServerSeed (byte[] server_seed) throws IOException
          {
            if (server_seed.length > 32 || server_seed.length == 0)
              {
                bad ("Server seed must be 1-32 bytes");
              }
            this.server_seed = server_seed;
            return this;
          }
        

        boolean enable_pin_caching;
        
        public KeyProperties setEnablePINCaching (boolean flag)
          {
            enable_pin_caching = flag;
            return this;
          }
        
        public boolean getEnablePINCachingFlag ()
          {
            return enable_pin_caching;
          }


        BiometricProtection biometric_protection;
        
        public KeyProperties setBiometricProtection (BiometricProtection biometric_protection) throws IOException
          {
            // TODO there must be some PIN-related tests here...
            this.biometric_protection = biometric_protection;
            return this;
          }

        public BiometricProtection getBiometricProtection ()
          {
            return biometric_protection;
          }


        DeleteProtection delete_protection;
        
        public KeyProperties setDeleteProtection (DeleteProtection delete_protection) throws IOException
          {
            // TODO there must be some PIN-related tests here...
            this.delete_protection = delete_protection;
            return this;
          }

        public DeleteProtection getDeletePolicy ()
          {
            return delete_protection;
          }


        String id;

        public String getID ()
          {
            return id;
          }
        

        AppUsage app_usage;

        public AppUsage getAppUsage ()
          {
            return app_usage;
          }

        KeySpecifier key_specifier;

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
        

        boolean device_pin_protection;

        public boolean getDevicePINProtection ()
          {
            return device_pin_protection;
          }
        
        
        void setPostOp (PostProvisioningTargetKey op) throws IOException
          {
            if (clone_or_update_operation != null)
              {
                bad ("Clone or Update already set for this key");
              }
            if (pin_policy != null || device_pin_protection)
              {
                bad ("Clone/Update keys cannot be PIN protected");
              }
            clone_or_update_operation = op;
          }
        
     
        public KeyProperties setClonedKeyProtection (String old_client_session_id, 
                                           String old_server_session_id,
                                           X509Certificate old_key,
                                           PublicKey key_management_key) throws IOException, GeneralSecurityException
          {
            PostProvisioningTargetKey op = addPostOperation (old_client_session_id,
                                                             old_server_session_id,
                                                             old_key,
                                                             PostOperation.CLONE_KEY_PROTECTION,
                                                             key_management_key);
            setPostOp (op);
            return this;
          }

        public KeyProperties setUpdatedKey (String old_client_session_id, 
                                            String old_server_session_id,
                                            X509Certificate old_key,
                                            PublicKey key_management_key) throws IOException, GeneralSecurityException
          { 
            PostProvisioningTargetKey op = addPostOperation (old_client_session_id,
                                                             old_server_session_id,
                                                             old_key,
                                                             PostOperation.UPDATE_KEY,
                                                             key_management_key);
            setPostOp (op);
            return this;
          }

        KeyProperties (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protection) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.app_usage = app_usage;
            this.key_specifier = key_specifier;
            this.pin_policy = pin_policy;
            this.preset_pin = preset_pin;
            this.device_pin_protection = device_pin_protection;
            if (pin_policy != null)
              {
                if (pin_policy.not_first)
                  {
                    if (pin_policy.grouping == Grouping.SHARED && ((pin_policy.preset_test == null && preset_pin != null) || (pin_policy.preset_test != null && preset_pin == null)))
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

        void writeRequest (DOMWriterHelper wr, ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
          {
            key_init_done = true;
            MacGenerator key_pair_mac = new MacGenerator ();
            key_pair_mac.addString (id);
            key_pair_mac.addString (key_attestation_algorithm);
            key_pair_mac.addArray (server_seed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : server_seed);
            key_pair_mac.addString (pin_policy == null ? 
                                      device_pin_protection ?
                                          SecureKeyStore.CRYPTO_STRING_DEVICE_PIN
                                                           : 
                                          SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE 
                                                       :
                                      pin_policy.id);
            if (getEncryptedPIN () == null)
              {
                key_pair_mac.addString (SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
              }
            else
              {
                key_pair_mac.addArray (getEncryptedPIN ());
              }
            key_pair_mac.addBool (enable_pin_caching);
            key_pair_mac.addByte (biometric_protection == null ?
                       BiometricProtection.NONE.getSKSValue () : biometric_protection.getSKSValue ());
            key_pair_mac.addByte (export_protection == null ?
                ExportProtection.NON_EXPORTABLE.getSKSValue () : export_protection.getSKSValue ());
            key_pair_mac.addByte (delete_protection == null ?
                       DeleteProtection.NONE.getSKSValue () : delete_protection.getSKSValue ());
            key_pair_mac.addByte (app_usage.getSKSValue ());
            key_pair_mac.addString (friendly_name == null ? "" : friendly_name);
            key_pair_mac.addArray (key_specifier.getSKSValue ());
            if (endorsed_algorithms != null) for (String algorithm : endorsed_algorithms)
              {
                key_pair_mac.addString (algorithm);
              }

            if (device_pin_protection)
              {
                wr.addChildElement (DEVICE_PIN_PROTECTION_ELEM);
              }
            if (preset_pin != null)
              {
                wr.addChildElement (PRESET_PIN_ELEM);
                preset_pin.write (wr);
              }
            wr.addChildElement (KEY_ENTRY_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setStringAttribute (APP_USAGE_ATTR, app_usage.getXMLName ());

            if (export_protection != null)
              {
                wr.setStringAttribute (EXPORT_PROTECTION_ATTR, export_protection.getXMLName ());
              }

            if (endorsed_algorithms != null)
              {
                wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, endorsed_algorithms);
              }

            if (biometric_protection != null)
              {
                wr.setStringAttribute (BIOMETRIC_PROTECTION_ATTR, biometric_protection.getXMLName ());
              }
            
            if (delete_protection != null)
              {
                wr.setStringAttribute (DELETE_PROTECTION_ATTR, delete_protection.getXMLName ());
              }
            
            if (server_seed != null)
              {
                wr.setBinaryAttribute (SERVER_SEED_ATTR, server_seed);
              }

            wr.setBinaryAttribute (MAC_ATTR, mac (key_pair_mac.getResult (), SecureKeyStore.METHOD_CREATE_KEY_ENTRY, server_crypto_interface));
            
            expected_attest_mac_count = getMACSequenceCounterAndUpdate ();
            
            key_specifier.writeKeySpecifier (wr);

            wr.getParent ();

            if (device_pin_protection || preset_pin != null)
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
    
    String key_attestation_algorithm;
    
    byte[] saved_close_nonce;
    
    X509Certificate device_certificate;
    
    PostProvisioningTargetKey addPostOperation (String old_client_session_id,
                                                String old_server_session_id,
                                                X509Certificate old_key,
                                                PostOperation operation,
                                                PublicKey key_management_key) throws IOException, GeneralSecurityException
      {
        PostProvisioningTargetKey new_post_op = new PostProvisioningTargetKey (old_client_session_id,
                                                                               old_server_session_id,
                                                                               old_key.getEncoded (),
                                                                               key_management_key,
                                                                               operation);
        for (PostProvisioningTargetKey post_op : post_operations)
          {
            if (post_op.equals (new_post_op))
              {
                if (post_op.post_operation == PostOperation.DELETE_KEY || new_post_op.post_operation == PostOperation.DELETE_KEY)
                  {
                    bad ("DeleteKey cannot be combined with other management operations");
                  }
                if (post_op.post_operation == PostOperation.UPDATE_KEY || new_post_op.post_operation == PostOperation.UPDATE_KEY)
                  {
                    bad ("UpdateKey can only be performed once per key");
                  }
              }
          }
        post_operations.add (new_post_op);
        return new_post_op;
      }
    
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

    byte[] mac (byte[] data, byte[] method, ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
      {
        return server_crypto_interface.mac (data, ArrayUtil.add (method, getMACSequenceCounterAndUpdate ()));
      }
    
    byte[] attest (byte[] data, byte[] mac_counter, ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
      {
        return server_crypto_interface.mac (data, ArrayUtil.add (SecureKeyStore.KDF_DEVICE_ATTESTATION, mac_counter)); 
      }
    
    void checkFinalResult (byte[] close_session_attestation,  ServerCryptoInterface server_crypto_interface) throws IOException, GeneralSecurityException
      {
        MacGenerator check = new MacGenerator ();
        check.addArray (saved_close_nonce);
        check.addString (KeyGen2URIs.ALGORITHMS.SESSION_KEY_1);
        if (!ArrayUtil.compare (attest (check.getResult (),
                                        getMACSequenceCounterAndUpdate (),
                                        server_crypto_interface),
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

    public ServerCredentialStore (ProvisioningInitializationResponseDecoder prov_sess_response,
                                  ProvisioningInitializationRequestEncoder prov_sess_request) throws IOException
      {
        this.client_session_id = prov_sess_response.client_session_id;
        this.server_session_id = prov_sess_request.server_session_id;
        this.issuer_uri = prov_sess_request.submit_url;
        this.device_certificate = prov_sess_response.device_certificate_path == null ? null : prov_sess_response.device_certificate_path[0];
       }
    
    
    public void addPostProvisioningDeleteKey (String old_client_session_id,
                                              String old_server_session_id,
                                              X509Certificate old_key,
                                              PublicKey key_management_key) throws IOException, GeneralSecurityException
      {
        addPostOperation (old_client_session_id, 
                          old_server_session_id,
                          old_key, 
                          PostOperation.DELETE_KEY,
                          key_management_key);
      }

  
    public void addPostProvisioningUnlockKey (String old_client_session_id,
                                              String old_server_session_id,
                                              X509Certificate old_key,
                                              PublicKey key_management_key) throws IOException, GeneralSecurityException
      {
        addPostOperation (old_client_session_id, 
        old_server_session_id,
        old_key, 
        PostOperation.UNLOCK_KEY,
        key_management_key);
      }

    
    public String getClientSessionID ()
      {
        return client_session_id;
      }

    public String getServerSessionID ()
      {
        return server_session_id;
      }

    
    public PINPolicy createPINPolicy (PassphraseFormat format, int min_length, int max_length, int retry_limit, PUKPolicy puk_policy) throws IOException
      {
        PINPolicy pin_policy = new PINPolicy ();
        pin_policy.format = format;
        pin_policy.min_length = min_length;
        pin_policy.max_length = max_length;
        pin_policy.retry_limit = retry_limit;
        pin_policy.puk_policy = puk_policy;
        if (format == null)
          {
            bad ("PassphraseFormat must not be null");
          }
        if (min_length > max_length)
          {
            bad ("min_length > max_length");
          }
        return pin_policy;
      }


    public PUKPolicy createPUKPolicy (byte[] encrypted_puk, PassphraseFormat format, int retry_limit) throws IOException
      {
        return new PUKPolicy (encrypted_puk, format, retry_limit);
      }


    private KeyProperties addKeyProperties (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy, PresetValue preset_pin, boolean device_pin_protection) throws IOException
      {
        KeyProperties key = new KeyProperties (app_usage, key_specifier, pin_policy, preset_pin, device_pin_protection);
        requested_keys.put (key.getID (), key);
        return key;
      }


    public KeyProperties createKeyWithPresetPIN (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy, byte[] encrypted_pin) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        return addKeyProperties (app_usage, key_specifier, pin_policy, new PresetValue (encrypted_pin), false);
      }


    public KeyProperties createKey (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy) throws IOException
      {
        KeyProperties key = addKeyProperties (app_usage, key_specifier, pin_policy, null, false);
        if (pin_policy != null)
          {
            pin_policy.user_defined = true;
            if (!pin_policy.user_modifiable_set)
              {
                pin_policy.user_modifiable = true;  // Default for user-defined PINs using KeyGen2
              }
          }
        return key;
      }


    public KeyProperties createDevicePINProtectedKey (AppUsage app_usage, KeySpecifier key_specifier) throws IOException
      {
        return addKeyProperties (app_usage, key_specifier, null, null, true);
      }

  }
