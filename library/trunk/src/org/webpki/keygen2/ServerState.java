/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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

import java.security.interfaces.ECPublicKey;

import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.Vector;

import org.webpki.crypto.DeviceID;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSymKeyVerifier;

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
import org.webpki.util.MIMETypedObject;

public class ServerState implements Serializable
  {
    private static final long serialVersionUID = 1L;
    
    public enum ProtocolPhase {INVOCATION,
                               PROVISIONING_INITIALIZATION,
                               CREDENTIAL_DISCOVERY,
                               KEY_CREATION,
                               PROVISIONING_FINALIZATION,
                               DONE};

    enum PostOperation
      {
        DELETE_KEY            (SecureKeyStore.METHOD_POST_DELETE_KEY,           DELETE_KEYS_JSON), 
        UNLOCK_KEY            (SecureKeyStore.METHOD_POST_UNLOCK_KEY,           UNLOCK_KEYS_JSON), 
        UPDATE_KEY            (SecureKeyStore.METHOD_POST_UPDATE_KEY,           UPDATE_KEY_JSON), 
        CLONE_KEY_PROTECTION  (SecureKeyStore.METHOD_POST_CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_JSON);
        
        private byte[] method;
        
        private String json_prop;
        
        PostOperation (byte[] method, String json_prop)
          {
            this.method = method;
            this.json_prop = json_prop;
          }

        byte[] getMethod ()
          {
            return method;
          }
        
        String getJSONProp ()
          {
            return json_prop;
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
        
        public String getQualifier () throws IOException
          {
            return "";
          }
        
        public abstract String getJSONArrayString ();
        
        public abstract byte[] getExtensionData () throws IOException;
        
        abstract void writeExtensionBody (JSONObjectWriter wr) throws IOException;
        
        ExtensionInterface (String type)
          {
            this.type = type;
          }

        void writeExtension (JSONObjectWriter wr, byte[] mac_data) throws IOException
          {
            wr.setString (TYPE_JSON, type);
            writeExtensionBody (wr);
            wr.setBinary (MAC_JSON, mac_data);
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

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }

        @Override
        void writeExtensionBody (JSONObjectWriter wr) throws IOException
          {
            wr.setBinary (EXTENSION_DATA_JSON, data);
          }

        @Override
        public String getJSONArrayString ()
          {
            return EXTENSIONS_JSON;
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

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            return encrypted_data;
          }
        
        @Override
        void writeExtensionBody (JSONObjectWriter wr) throws IOException
          {
            wr.setBinary (EXTENSION_DATA_JSON, encrypted_data);
          }

        @Override
        public String getJSONArrayString ()
          {
            return ENCRYPTED_EXTENSIONS_JSON;
          }
      }

    public class Logotype extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        MIMETypedObject logotype;

        Logotype (String type, MIMETypedObject logotype)
          {
            super (type);
            this.logotype = logotype;
          }

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            return logotype.getData ();
          }

        @Override
        public String getQualifier () throws IOException
          {
            return logotype.getMimeType ();
          }

        @Override
        void writeExtensionBody (JSONObjectWriter wr) throws IOException
          {
            wr.setString (MIME_TYPE_JSON, logotype.getMimeType ());
            wr.setBinary (EXTENSION_DATA_JSON, logotype.getData ());
          }

        @Override
        public String getJSONArrayString ()
          {
            return LOGOTYPES_JSON;
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
        
        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
          }
        
        @Override
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

        @Override
        void writeExtensionBody (JSONObjectWriter wr) throws IOException
          {
            if (properties.isEmpty ())
              {
                throw new IOException ("Empty " + PROPERTY_BAGS_JSON + ": " + type);
              }
            JSONArrayWriter arr = wr.setArray (PROPERTIES_JSON);
            for (Property property : properties.values ())
              {
                JSONObjectWriter prop_wr = arr.setObject ();
                prop_wr.setString (NAME_JSON, property.name);
                prop_wr.setString (VALUE_JSON, property.value);
                if (property.writable)
                  {
                    prop_wr.setBoolean (WRITABLE_JSON, property.writable);
                  }
              }
          }

        @Override
        public String getJSONArrayString ()
          {
            return PROPERTY_BAGS_JSON;
          }
      }


    public class PUKPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String id;
        
        byte[] encrypted_value;

        public String getID ()
          {
            return id;
          }

        PassphraseFormat format;

        int retry_limit;

        PUKPolicy (byte[] encrypted_value, PassphraseFormat format, int retry_limit) throws IOException
          {
            this.encrypted_value = encrypted_value;
            this.id = puk_prefix + ++next_puk_id_suffix;
            this.format = format;
            this.retry_limit = retry_limit;
            puk_policies.add (this);
          }

        void writePolicy (JSONObjectWriter wr) throws IOException
          {
            wr.setString (ID_JSON, id);
            wr.setBinary (ENCRYPTED_PUK_JSON, encrypted_value);
            wr.setInt (RETRY_LIMIT_JSON, retry_limit);
            wr.setString (FORMAT_JSON, format.getProtocolName ());

            MacGenerator puk_policy_mac = new MacGenerator ();
            puk_policy_mac.addString (id);
            puk_policy_mac.addArray (encrypted_value);
            puk_policy_mac.addByte (format.getSksValue ());
            puk_policy_mac.addShort (retry_limit);
            wr.setBinary (MAC_JSON, mac (puk_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PUK_POLICY));
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


        boolean user_modifiable = true;
        
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
        
        boolean user_defined = true;
        
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
            pin_policies.add (this);
          }

        void writePolicy (JSONObjectWriter wr) throws IOException
          {
            wr.setString (ID_JSON, id);
            wr.setInt (MIN_LENGTH_JSON, min_length);
            wr.setInt (MAX_LENGTH_JSON, max_length);
            wr.setInt (RETRY_LIMIT_JSON, retry_limit);
            wr.setString (FORMAT_JSON, format.getProtocolName ());
            if (user_modifiable_set)
              {
                wr.setBoolean (USER_MODIFIABLE_JSON, user_modifiable);
              }
            if (grouping != null)
              {
                wr.setString (GROUPING_JSON, grouping.getProtocolName ());
              }
            if (input_method != null)
              {
                wr.setString (INPUT_METHOD_JSON, input_method.getProtocolName ());
              }
            if (!pattern_restrictions.isEmpty ())
              {
                Vector<String> prs = new Vector<String> ();
                for (PatternRestriction pr : pattern_restrictions)
                  {
                    prs.add (pr.getProtocolName ());
                  }
                wr.setStringArray (PATTERN_RESTRICTIONS_JSON, prs.toArray (new String[0]));
              }

            MacGenerator pin_policy_mac = new MacGenerator ();
            pin_policy_mac.addString (id);
            pin_policy_mac.addString (puk_policy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : puk_policy.id);
            pin_policy_mac.addBool (user_defined);
            pin_policy_mac.addBool (user_modifiable);
            pin_policy_mac.addByte (format.getSksValue ());
            pin_policy_mac.addShort (retry_limit);
            pin_policy_mac.addByte (grouping == null ? Grouping.NONE.getSksValue () : grouping.getSksValue ());
            pin_policy_mac.addByte (PatternRestriction.getSksValue (pattern_restrictions));
            pin_policy_mac.addShort (min_length);
            pin_policy_mac.addShort (max_length);
            pin_policy_mac.addByte (input_method == null ? InputMethod.ANY.getSksValue () : input_method.getSksValue ());
            wr.setBinary (MAC_JSON, mac (pin_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PIN_POLICY));
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


    public class Key implements Serializable
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
        
        public Key setUserObject (Object object)
          {
            this.object = object;
            return this;
          }
        
        public Object getUserObject ()
          {
            return object;
          }


        public Key addExtension (String type, byte[] data) throws IOException
          {
            addExtension (new Extension (type, data));
            return this;
          }

        public Key addEncryptedExtension (String type, byte[] data) throws IOException
          {
            addExtension (new EncryptedExtension (type, encrypt (data)));
            return this;
          }

        public Key addLogotype (String type, MIMETypedObject logotype) throws IOException
          {
            addExtension (new Logotype (type, logotype));
            return this;
          }


        X509Certificate[] certificate_path;
        
        public Key setCertificatePath (X509Certificate[] certificate_path)
          {
            this.certificate_path = certificate_path;
            return this;
          }
        
        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
          }


        byte[] encrypted_symmetric_key;
        
        public Key setSymmetricKey (byte[] symmetric_key) throws IOException
          {
            this.encrypted_symmetric_key = encrypt (symmetric_key);
            return this;
          }

        String[] getSortedAlgorithms (String[] algorithms) throws IOException
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

        String[] endorsed_algorithms;

        public Key setEndorsedAlgorithms (String[] endorsed_algorithms) throws IOException
          {
            this.endorsed_algorithms = getSortedAlgorithms (endorsed_algorithms);
            return this;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        byte[] encrypted_private_key;
        
        public Key setPrivateKey (byte[] private_key) throws IOException
          {
            this.encrypted_private_key = encrypt (private_key);
            return this;
          }

        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }

        
        String friendly_name;

        public Key setFriendlyName (String friendly_name)
          {
            this.friendly_name = friendly_name;
            return this;
          }

        public String getFriendlyName ()
          {
            return friendly_name;
          }

        
        PublicKey publicKey;   // Filled in by KeyCreationRequestDecoder

        public PublicKey getPublicKey ()
          {
            return publicKey;
          }


        byte[] attestation;   // Filled in by KeyCreationRequestDecoder
        
        public byte[] getAttestation ()
          {
            return attestation;
          }


        ExportProtection export_protection;
        
        public Key setExportProtection (ExportProtection export_protection)
          {
            this.export_protection = export_protection;
            return this;
          }

        public ExportProtection getExportPolicy ()
          {
            return export_protection;
          }
        
        
        byte[] server_seed;
        
        public Key setServerSeed (byte[] server_seed) throws IOException
          {
            if (server_seed != null && server_seed.length > SecureKeyStore.MAX_LENGTH_SERVER_SEED)
              {
                bad ("Server seed > " + SecureKeyStore.MAX_LENGTH_SERVER_SEED + " bytes");
              }
            this.server_seed = server_seed;
            return this;
          }
        

        boolean enable_pin_caching;
        boolean enable_pin_caching_set;
        
        public Key setEnablePINCaching (boolean flag)
          {
            enable_pin_caching = flag;
            enable_pin_caching_set = true;
            return this;
          }
        
        public boolean getEnablePINCachingFlag ()
          {
            return enable_pin_caching;
          }


        boolean trust_anchor;
        boolean trust_anchor_set;
        
        public Key setTrustAnchor (boolean flag)
          {
            trust_anchor = flag;
            trust_anchor_set = true;
            return this;
          }
        
        public boolean getTrustAnchorFlag ()
          {
            return trust_anchor;
          }

        
        BiometricProtection biometric_protection;
        
        public Key setBiometricProtection (BiometricProtection biometric_protection) throws IOException
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
        
        public Key setDeleteProtection (DeleteProtection delete_protection) throws IOException
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
        
        public Key setID (String new_id) throws IOException
          {
            requested_keys.remove (id);
            id = KeyGen2Validator.validateID (ID_JSON, new_id);
            return addKeyToRequestList (this);
          }
        

        AppUsage app_usage;

        public AppUsage getAppUsage ()
          {
            return app_usage;
          }

        KeySpecifier keySpecifier;

        PINPolicy pin_policy;
        
        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }

        
        byte[] preset_pin;
        
        public byte[] getEncryptedPIN ()
          {
            return preset_pin;
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
        
     
        public Key setClonedKeyProtection (String old_client_session_id, 
                                           String old_server_session_id,
                                           X509Certificate old_key,
                                           PublicKey key_management_key) throws IOException
          {
            PostProvisioningTargetKey op = addPostOperation (old_client_session_id,
                                                             old_server_session_id,
                                                             old_key,
                                                             PostOperation.CLONE_KEY_PROTECTION,
                                                             key_management_key);
            setPostOp (op);
            return this;
          }

        public Key setUpdatedKey (String old_client_session_id, 
                                  String old_server_session_id,
                                  X509Certificate old_key,
                                  PublicKey key_management_key) throws IOException
          { 
            PostProvisioningTargetKey op = addPostOperation (old_client_session_id,
                                                             old_server_session_id,
                                                             old_key,
                                                             PostOperation.UPDATE_KEY,
                                                             key_management_key);
            setPostOp (op);
            return this;
          }

        Key (AppUsage app_usage,
             KeySpecifier key_specifier,
             PINPolicy pin_policy,
             byte[] preset_pin,
             boolean device_pin_protection) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.app_usage = app_usage;
            this.keySpecifier = key_specifier;
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
                    pin_policy.preset_test = preset_pin;
                  }
              }
          }

        void writeRequest (JSONObjectWriter wr) throws IOException
          {
            key_init_done = true;
            MacGenerator key_pair_mac = new MacGenerator ();
            key_pair_mac.addString (id);
            key_pair_mac.addString (key_attestation_algorithm);
            key_pair_mac.addArray (server_seed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : server_seed);
            key_pair_mac.addString (pin_policy == null ? 
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
            key_pair_mac.addBool (device_pin_protection);
            key_pair_mac.addBool (enable_pin_caching);
            key_pair_mac.addByte (biometric_protection == null ?
                       BiometricProtection.NONE.getSksValue () : biometric_protection.getSksValue ());
            key_pair_mac.addByte (export_protection == null ?
                ExportProtection.NON_EXPORTABLE.getSksValue () : export_protection.getSksValue ());
            key_pair_mac.addByte (delete_protection == null ?
                       DeleteProtection.NONE.getSksValue () : delete_protection.getSksValue ());
            key_pair_mac.addByte (app_usage.getSksValue ());
            key_pair_mac.addString (friendly_name == null ? "" : friendly_name);
            key_pair_mac.addString (keySpecifier.getKeyAlgorithm ().getURI ());
            key_pair_mac.addArray (keySpecifier.getKeyParameters () == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keySpecifier.getKeyParameters ());
            if (endorsed_algorithms != null) for (String algorithm : endorsed_algorithms)
              {
                key_pair_mac.addString (algorithm);
              }

            wr.setString (ID_JSON, id);

            if (server_seed != null)
              {
                wr.setBinary (SERVER_SEED_JSON, server_seed);
              }

            if (device_pin_protection)
              {
                wr.setBoolean (DEVICE_PIN_PROTECTION_JSON, true);
              }

            if (preset_pin != null)
              {
                wr.setBinary (ENCRYPTED_PIN_JSON, preset_pin);
              }

            if (enable_pin_caching_set)
              {
                if (enable_pin_caching && (pin_policy == null || pin_policy.input_method != InputMethod.TRUSTED_GUI))
                  {
                    bad ("\"" + ENABLE_PIN_CACHING_JSON +"\" must be combined with " + InputMethod.TRUSTED_GUI.toString ());
                  }
                wr.setBoolean (ENABLE_PIN_CACHING_JSON, enable_pin_caching);
              }

            if (biometric_protection != null)
              {
                wr.setString (BIOMETRIC_PROTECTION_JSON, biometric_protection.getProtocolName ());
              }

            if (export_protection != null)
              {
                wr.setString (EXPORT_PROTECTION_JSON, export_protection.getProtocolName ());
              }

            if (delete_protection != null)
              {
                wr.setString (DELETE_PROTECTION_JSON, delete_protection.getProtocolName ());
              }

            if (friendly_name != null)
              {
                wr.setString (FRIENDLY_NAME_JSON, friendly_name);
              }

            wr.setString (APP_USAGE_JSON, app_usage.getProtocolName ());

            wr.setString (KEY_ALGORITHM_JSON, keySpecifier.getKeyAlgorithm ().getURI ());
            if (keySpecifier.getKeyParameters () != null)
              {
                wr.setBinary (KEY_PARAMETERS_JSON, keySpecifier.getKeyParameters ());
              }

            if (endorsed_algorithms != null && endorsed_algorithms.length > 0)
              {
                wr.setStringArray (ENDORSED_ALGORITHMS_JSON, endorsed_algorithms);
              }

            wr.setBinary (MAC_JSON, mac (key_pair_mac.getResult (), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));
            
            expected_attest_mac_count = getMacSequenceCounterAndUpdate ();
          }
      }

    public Key[] getKeys ()
      {
        return requested_keys.values ().toArray (new Key[0]);
      }

    public ProtocolPhase getProtocolPhase ()
      {
        return current_phase;
      }

    ServerCryptoInterface server_crypto_interface;

    enum CAPABILITY {UNDEFINED, URI_FEATURE, VALUES, IMAGE_ATTRIBUTES};
    
    LinkedHashMap<String,CAPABILITY> queried_capabilities = new LinkedHashMap<String,CAPABILITY> ();   

    static abstract class CapabilityBase implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String type;
        
        CAPABILITY capability = CAPABILITY.URI_FEATURE;
        
        boolean supported = true;
        
        public String getType ()
          {
            return type;
          }
  
        boolean isSupported ()
          {
            return supported;
          }
      }
    
    public static class ImagePreference extends CapabilityBase
      {
        private static final long serialVersionUID = 1L;

        String mime_type;
        int width;
        int height;
  
        ImagePreference (String mime_type, int width, int height)
          {
            this.mime_type = mime_type;
            this.width = width;
            this.height = height;
            super.capability = CAPABILITY.IMAGE_ATTRIBUTES;
          }
  
        public String getMimeType ()
          {
            return mime_type;
          }
  
        public int getWidth ()
          {
            return width;
          }
  
        public int getHeight ()
          {
            return height;
          }
      }
  
    static class Values extends CapabilityBase
      {
        private static final long serialVersionUID = 1L;

        String[] values;
        
        Values (String[] values)
          {
  
            this.values = values;
            super.capability = CAPABILITY.VALUES;
          }
        
        public String[] getValues ()
          {
            return values;
          }
      }
    
    static class Feature extends CapabilityBase
      {
        private static final long serialVersionUID = 1L;

        Feature (boolean supported)
          {
            this.supported = supported;
          }
      }

    LinkedHashMap<String,CapabilityBase> received_capabilities;

    CapabilityBase getCapability (String type_uri, CAPABILITY what) throws IOException
      {
        CapabilityBase capability = received_capabilities.get (type_uri);
        if (capability != null && capability.isSupported ())
          {
            if (capability.capability != what)
              {
                bad ("Type error for capability: " + type_uri);
              }
            return capability;
          }
        return null;
      }

    public ImagePreference getImagePreference (String image_type_uri) throws IOException
      {
        return (ImagePreference) getCapability (image_type_uri, CAPABILITY.IMAGE_ATTRIBUTES);
      }
    
    public String[] getValuesCapability (String values_type_uri) throws IOException
      {
        Values values = (Values) getCapability (values_type_uri, CAPABILITY.VALUES);
        return values == null ? null : values.getValues (); 
      }
  
    public boolean isFeatureSupported (String feature_type_uri) throws IOException
      {
        return getCapability (feature_type_uri, CAPABILITY.URI_FEATURE) != null;
      }
    
    ProtocolPhase current_phase = ProtocolPhase.INVOCATION;
    
    boolean request_phase = true;
    
    int next_personal_code = 1;

    String key_prefix = "Key.";

    int next_key_id_suffix = 0;

    String pin_prefix = "PIN.";

    int next_pin_id_suffix = 0;

    String puk_prefix = "PUK.";

    int next_puk_id_suffix = 0;

    short mac_sequence_counter;

    LinkedHashMap<String,Key> requested_keys = new LinkedHashMap<String,Key> ();

    String server_session_id;

    String client_session_id;
    
    String issuer_uri;

    int session_life_time;

    short session_key_limit;
    
    String provisioning_session_algorithm = SecureKeyStore.ALGORITHM_SESSION_ATTEST_1;
    
    String key_attestation_algorithm;
    
    ECPublicKey server_ephemeral_key;
    
    ECPublicKey client_ephemeral_key;
    
    PublicKey key_management_key;
    
    byte[] saved_close_nonce;
    
    byte[] ve_nonce;
    
    X509Certificate[] device_certificate_path;
    
    PostProvisioningTargetKey addPostOperation (String old_client_session_id,
                                                String old_server_session_id,
                                                X509Certificate old_key,
                                                PostOperation operation,
                                                PublicKey key_management_key) throws IOException
      {
        try
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
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
    
    void checkSession (String client_session_id, String server_session_id) throws IOException
      {
        if (!this.client_session_id.equals (client_session_id) || !this.server_session_id.equals (server_session_id))
          {
            bad ("Session ID mismatch");
          }
      }
    
    private byte[] getMacSequenceCounterAndUpdate ()
      {
        int q = mac_sequence_counter++;
        return  new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
      }

    byte[] mac (byte[] data, byte[] method) throws IOException
      {
        return server_crypto_interface.mac (data, ArrayUtil.add (method, getMacSequenceCounterAndUpdate ()));
      }
    
    byte[] attest (byte[] data, byte[] mac_counter) throws IOException
      {
        return server_crypto_interface.mac (data, ArrayUtil.add (SecureKeyStore.KDF_DEVICE_ATTESTATION, mac_counter)); 
      }
    
    byte[] encrypt (byte[] data) throws IOException
      {
        return server_crypto_interface.encrypt (data);
      }
    
    void checkFinalResult (byte[] close_session_attestation) throws IOException, GeneralSecurityException
      {
        MacGenerator check = new MacGenerator ();
        check.addArray (saved_close_nonce);
        check.addString (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1);
        if (!ArrayUtil.compare (attest (check.getResult (),
                                        getMacSequenceCounterAndUpdate ()),
                                close_session_attestation))
          {
            bad ("Final attestation failed!");
          }
      }
  
    static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }
    
    boolean privacy_enabled;
    boolean privacy_enabled_set;
    
    public void setPrivacyEnabled (boolean flag) throws IOException
      {
        if (!request_phase || current_phase != ProtocolPhase.INVOCATION)
          {
            throw new IOException ("Must be specified before any requests");
          }
        privacy_enabled_set = true;
        privacy_enabled = flag;
      }


    KeyAlgorithms ephemeral_key_algorithm = KeyAlgorithms.NIST_P_256;
    
    public void setEphemeralKeyAlgorithm (KeyAlgorithms ephemeral_key_algorithm)
      {
        this.ephemeral_key_algorithm = ephemeral_key_algorithm;
      }


    String[] language_list;

    public void setPreferredLanguages (String[] optional_language_list)
      {
        this.language_list = optional_language_list;
      }


    String[] key_container_list;
    
    public void setTargetKeyContainerList (KeyContainerTypes[] optional_key_container_list) throws IOException
      {
        this.key_container_list = KeyContainerTypes.parseOptionalKeyContainerList (optional_key_container_list);
      }
 

    // Constructor
    public ServerState (ServerCryptoInterface server_crypto_interface)
      {
        this.server_crypto_interface = server_crypto_interface;
      }

    ServerState addQuery (String type_uri, CAPABILITY what) throws IOException
      {
        CAPABILITY existing = queried_capabilities.get (type_uri);
        if (existing != null)
          {
            throw new IOException ("Duplicate request URI: " + type_uri);
          }
        queried_capabilities.put (type_uri, what);
        return this;
      }

    public ServerState addFeatureQuery (String feature_type_uri) throws IOException
      {
        return addQuery (feature_type_uri, CAPABILITY.URI_FEATURE);
      }
    
    public ServerState addValuesQuery (String values_type_uri) throws IOException
      {
        return addQuery (values_type_uri, CAPABILITY.VALUES);
      }

    public ServerState addImageAttributesQuery (String image_type_uri) throws IOException
      {
        return addQuery (image_type_uri, CAPABILITY.IMAGE_ATTRIBUTES);
      }

    void checkState (boolean request, ProtocolPhase expected) throws IOException
      {
        if (request ^ request_phase)
          {
            throw new IOException ("Wrong order of request versus response");
          }
        request_phase = !request_phase;
        if (current_phase != expected)
          {
            throw new IOException ("Incorrect object, expected: " + expected + " got: " + current_phase);
          }
      }


    public void update (InvocationResponseDecoder invocation_response) throws IOException
      {
        checkState (false, ProtocolPhase.INVOCATION);
        current_phase = ProtocolPhase.PROVISIONING_INITIALIZATION;
        if (queried_capabilities.size () != invocation_response.received_capabilities.size ())
          {
            bad ("Differing length of queried versus received capabilities");
          }
        received_capabilities = invocation_response.received_capabilities;
        for (String capability : queried_capabilities.keySet ())
          {
            CAPABILITY queried = queried_capabilities.get (capability);
            CapabilityBase received = received_capabilities.get (capability);
            if (received == null)
              {
                bad ("Missing capability: " + capability);
              }
            if (received.supported && queried != received.capability)
              {
                bad ("Non-matching capability for URI: " + capability);
              }
          }
        ve_nonce = invocation_response.nonce;
      }


    public void update (ProvisioningInitializationResponseDecoder prov_init_response, X509Certificate server_certificate) throws IOException
      {
        try
          {
            checkState (false, ProtocolPhase.PROVISIONING_INITIALIZATION);
            client_session_id = prov_init_response.client_session_id;
            device_certificate_path = prov_init_response.device_certificate_path;
            client_ephemeral_key = prov_init_response.client_ephemeral_key;

            MacGenerator kdf = new MacGenerator ();
            kdf.addString (client_session_id);
            kdf.addString (server_session_id);
            kdf.addString (issuer_uri);
            kdf.addArray (getDeviceID ());

            MacGenerator attestation_arguments = new MacGenerator ();
            attestation_arguments.addString (client_session_id);
            attestation_arguments.addString (server_session_id);
            attestation_arguments.addString (issuer_uri);
            attestation_arguments.addArray (getDeviceID ());
            attestation_arguments.addString (provisioning_session_algorithm);
            attestation_arguments.addBool (getDeviceCertificate () == null);
            attestation_arguments.addArray (server_ephemeral_key.getEncoded ());
            attestation_arguments.addArray (client_ephemeral_key.getEncoded ());
            attestation_arguments.addArray (key_management_key == null ? new byte[0] : key_management_key.getEncoded ());
            attestation_arguments.addInt ((int) (prov_init_response.client_time.getTime () / 1000));
            attestation_arguments.addInt (session_life_time);
            attestation_arguments.addShort (session_key_limit);

            server_crypto_interface.generateAndVerifySessionKey (client_ephemeral_key,
                                                                 kdf.getResult (),
                                                                 attestation_arguments.getResult (),
                                                                 getDeviceCertificate (),
                                                                 prov_init_response.attestation);
            if (((server_certificate == null ^ prov_init_response.server_certificate_fingerprint == null)) ||
                (server_certificate != null && !ArrayUtil.compare (prov_init_response.server_certificate_fingerprint, 
                                                                   HashAlgorithms.SHA256.digest (server_certificate.getEncoded ()))))
              {
                bad ("Attribute '" + SERVER_CERT_FP_JSON + "' is missing or is invalid");
              }
            prov_init_response.signature.verify (new JSONSymKeyVerifier (new SymKeyVerifierInterface()
              {
                @Override
                public boolean verifyData (byte[] data, byte[] digest, MACAlgorithms algorithm, String key_id) throws IOException
                  {
                    return ArrayUtil.compare (server_crypto_interface.mac (data, SecureKeyStore.KDF_EXTERNAL_SIGNATURE), digest);
                  }
              }));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        current_phase = ProtocolPhase.CREDENTIAL_DISCOVERY;
      }


    byte[] getDeviceID () throws GeneralSecurityException
      {
        return getDeviceCertificate () == null ? SecureKeyStore.KDF_ANONYMOUS : getDeviceCertificate ().getEncoded ();
      }

    public void update (CredentialDiscoveryResponseDecoder credential_discovery_response) throws IOException
      {
        checkState (false, ProtocolPhase.CREDENTIAL_DISCOVERY);
        checkSession (credential_discovery_response.client_session_id, credential_discovery_response.server_session_id);
        current_phase = ProtocolPhase.KEY_CREATION;
      }


    public void update (KeyCreationResponseDecoder key_create_response) throws IOException
      {
        checkState (false, ProtocolPhase.KEY_CREATION);
        checkSession (key_create_response.client_session_id, key_create_response.server_session_id);
        if (key_create_response.generated_keys.size () != requested_keys.size ())
          {
            ServerState.bad ("Different number of requested and received keys");
          }
        Iterator<ServerState.Key> req_key_iterator = requested_keys.values ().iterator ();
        for (KeyCreationResponseDecoder.GeneratedPublicKey gpk : key_create_response.generated_keys.values ())
          {
            ServerState.Key kp = req_key_iterator.next ();
            if (!kp.id.equals (gpk.id))
              {
                ServerState.bad ("Wrong ID order:" + gpk.id + " / " + kp.id);
              }
            if (kp.keySpecifier.keyAlgorithm != KeyAlgorithms.getKeyAlgorithm (kp.publicKey = gpk.publicKey, kp.keySpecifier.keyParameters != null))
              {
                ServerState.bad ("Wrong key type returned for key id:" + gpk.id);
              }
            MacGenerator attestation = new MacGenerator ();
            // Write key attestation data
            attestation.addString (gpk.id);
            attestation.addArray (gpk.publicKey.getEncoded ());
            if (!ArrayUtil.compare (attest (attestation.getResult (), kp.expected_attest_mac_count),
                                    kp.attestation = gpk.attestation))
              {
                ServerState.bad ("Attestation failed for key id:" + gpk.id);
              }
          }
        current_phase = ProtocolPhase.PROVISIONING_FINALIZATION;
      }

    
    public void update (ProvisioningFinalizationResponseDecoder prov_final_response) throws IOException
      {
        checkState (false, ProtocolPhase.PROVISIONING_FINALIZATION);
        checkSession (prov_final_response.client_session_id, prov_final_response.server_session_id);
        try
          {
            checkFinalResult (prov_final_response.attestation);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        current_phase = ProtocolPhase.DONE;
      }

    public X509Certificate getDeviceCertificate ()
      {
        return device_certificate_path == null ? null : device_certificate_path[0];
      }
    
    public String getDeviceIDString (boolean long_version)
      {
        return DeviceID.getDeviceID (getDeviceCertificate (), long_version);
      }


    public X509Certificate[] getDeviceCertificatePath ()
      {
        return device_certificate_path;
      }
   

    public void addPostDeleteKey (String old_client_session_id,
                                  String old_server_session_id,
                                  X509Certificate old_key,
                                  PublicKey key_management_key) throws IOException
      {
        addPostOperation (old_client_session_id, 
                          old_server_session_id,
                          old_key, 
                          PostOperation.DELETE_KEY,
                          key_management_key);
      }

  
    public void addPostUnlockKey (String old_client_session_id,
                                  String old_server_session_id,
                                  X509Certificate old_key,
                                  PublicKey key_management_key) throws IOException
      {
        addPostOperation (old_client_session_id, 
        old_server_session_id,
        old_key, 
        PostOperation.UNLOCK_KEY,
        key_management_key);
      }

    
    public String getClientSessionId ()
      {
        return client_session_id;
      }

    public String getServerSessionId ()
      {
        return server_session_id;
      }

    Vector<PINPolicy> pin_policies = new Vector<PINPolicy> ();
    
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

    Vector<PUKPolicy> puk_policies = new Vector<PUKPolicy> ();

    public PUKPolicy createPUKPolicy (byte[] puk, PassphraseFormat format, int retry_limit) throws IOException
      {
        return new PUKPolicy (encrypt (puk), format, retry_limit);
      }

    private Key addKeyToRequestList (Key key) throws IOException
      {
        if (key.key_init_done)
          {
            bad ("Can't initialize key at this [late] stage");
          }
        if (requested_keys.put (key.getID (), key) != null)
          {
            bad ("Duplicate definition: " + key.getID ());
          }
        return key;
      }

    private Key addKeyProperties (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy, byte[] preset_pin, boolean device_pin_protection) throws IOException
      {
        return addKeyToRequestList (new Key (app_usage, key_specifier, pin_policy, preset_pin, device_pin_protection));
      }


    public Key createKeyWithPresetPIN (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy, byte[] pin) throws IOException
      {
        if (pin_policy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        pin_policy.user_defined = false;
        return addKeyProperties (app_usage, key_specifier, pin_policy, encrypt (pin), false);
      }


    public Key createKey (AppUsage app_usage, KeySpecifier key_specifier, PINPolicy pin_policy) throws IOException
      {
        return addKeyProperties (app_usage, key_specifier, pin_policy, null, false);
      }


    public Key createDevicePINProtectedKey (AppUsage app_usage, KeySpecifier key_specifier) throws IOException
      {
        return addKeyProperties (app_usage, key_specifier, null, null, true);
      }


    private LinkedHashMap<String,Object> service_specific_objects = new LinkedHashMap<String,Object> ();
    
    public void setServiceSpecificObject (String name, Object value)
      {
        service_specific_objects.put (name, value);
      }


    public Object getServiceSpecificObject (String name)
      {
        return service_specific_objects.get (name);
      }

    public ECPublicKey generateEphemeralKey () throws IOException
      {
        return server_crypto_interface.generateEphemeralKey (ephemeral_key_algorithm);
      }
  }
