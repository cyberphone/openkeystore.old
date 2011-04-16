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

import java.io.IOException;

import java.util.Vector;
import java.util.Set;
import java.util.EnumSet;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.SecureKeyStore;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.ECDomains;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationRequestDecoder extends KeyCreationRequest
  {
    abstract class PresetValueReference
      {
        byte[] encrypted_value;

        PresetValueReference (DOMReaderHelper rd) throws IOException
          {
            encrypted_value = rd.getAttributeHelper ().getBinary (VALUE_ATTR);
          }
        
        public byte[] getEncryptedValue ()
          {
            return encrypted_value;
          }

      }


    public class PresetPIN extends PresetValueReference
      {
        boolean user_modifiable;

        PresetPIN (DOMReaderHelper rd) throws IOException
          {
            super (rd);
            user_modifiable = rd.getAttributeHelper ().getBooleanConditional (USER_MODIFIABLE_ATTR);
          }


        public boolean isUserModifiable ()
          {
            return user_modifiable;
          }

      }


    public class PUKPolicy extends PresetValueReference
      {
        byte[] mac;
        
        Object user_data;

        PassphraseFormat format;

        short retry_limit;
        
        String id;
 
        PUKPolicy (DOMReaderHelper rd) throws IOException
          {
            super (rd);
            retry_limit = (short)rd.getAttributeHelper ().getInt (RETRY_LIMIT_ATTR);
            id = rd.getAttributeHelper ().getString (ID_ATTR);
            format = PassphraseFormat.getPassphraseFormatFromString (rd.getAttributeHelper ().getString (FORMAT_ATTR));
            mac = rd.getAttributeHelper ().getBinary (MAC_ATTR);
          }


        public short getRetryLimit ()
          {
            return retry_limit;
          }


        public PassphraseFormat getFormat ()
          {
            return format;
          }


        public void setUserData (Object user_data)
          {
            this.user_data = user_data;
          }


        public Object getUserData ()
          {
            return user_data;
          }

        
        public String getID ()
          {
            return id;
          }

        
        public byte[] getMAC ()
          {
            return mac;
          }
      }


    public class PINPolicy
      {
        byte[] mac;
        
        String id;
        
        PUKPolicy puk_policy;
        
        Object user_data;

        PassphraseFormat format;

        short retry_limit;

        byte min_length;

        byte max_length;

        Grouping group;

        InputMethod input_method;

        Set<PatternRestriction> pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);

        PINPolicy (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            
            mac = ah.getBinary (MAC_ATTR);
            
            id = ah.getString (ID_ATTR);

            min_length = (byte)ah.getInt (MIN_LENGTH_ATTR);

            max_length = (byte)ah.getInt (MAX_LENGTH_ATTR);

            if (min_length > max_length)
              {
                bad ("PIN length: min > max");
              }

            retry_limit = (short)ah.getInt (RETRY_LIMIT_ATTR);

            format = PassphraseFormat.getPassphraseFormatFromString (ah.getString (FORMAT_ATTR));

            group = Grouping.getPINGroupingFromString (ah.getStringConditional (GROUPING_ATTR,
                                                                                   Grouping.NONE.getXMLName ()));

            input_method = InputMethod.getMethodFromString (ah.getStringConditional (INPUT_METHOD_ATTR,
                                                                                     InputMethod.ANY.getXMLName ()));
            
            read_user_modifiable = ah.getStringConditional (USER_MODIFIABLE_ATTR) != null;
            user_modifiable = ah.getBooleanConditional (USER_MODIFIABLE_ATTR, false);

            String pr[] = ah.getListConditional (PATTERN_RESTRICTIONS_ATTR);
            if (pr != null)
              {
                for (String pattern : pr)
                  {
                    pattern_restrictions.add (PatternRestriction.getPatternRestrictionFromString (pattern));
                  }
              }
          }


        public Set<PatternRestriction> getPatternRestrictions ()
          {
            return pattern_restrictions;
          }


        public byte getMinLength ()
          {
            return min_length;
          }


        public byte getMaxLength ()
          {
            return max_length;
          }


        public short getRetryLimit ()
          {
            return retry_limit;
          }


        public PassphraseFormat getFormat ()
          {
            return format;
          }


        public Grouping getGrouping ()
          {
            return group;
          }


        boolean user_defined;
        
        public boolean getUserDefinedFlag ()
          {
            return user_defined;
          }


        boolean user_modifiable;
        
        boolean read_user_modifiable;
        
        public boolean getUserModifiableFlag ()
          {
            return user_modifiable;
          }


        public InputMethod getInputMethod ()
          {
            return input_method;
          }


        public String getID ()
          {
            return id;
          }


        public byte[] getMAC ()
          {
            return mac;
          }


        public void setUserData (Object user_data)
          {
            this.user_data = user_data;
          }


        public Object getUserData ()
          {
            return user_data;
          }

        
        public PUKPolicy getPUKPolicy ()
          {
            return puk_policy;
          }

      }


    public class KeyObject
      {
        String id;
        
        byte[] mac;
        
        boolean start_of_puk_group;

        boolean start_of_pin_group;

        PINPolicy pin_policy;

        PresetPIN preset_pin;

        boolean device_pin_protected;
        
        AppUsage app_usage;

        KeySpecifier key_specifier;
        
        KeyObject (DOMReaderHelper rd, 
                   PINPolicy pin_policy,
                   boolean start_of_pin_group, 
                   PresetPIN preset_pin,
                   boolean device_pin_protected) throws IOException
          {
            rd.getNext (KEY_ENTRY_ELEM);
            this.pin_policy = pin_policy;
            this.start_of_pin_group = start_of_pin_group;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;

            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

            id = ah.getString (ID_ATTR);

            mac = ah.getBinary (MAC_ATTR);

            friendly_name = ah.getStringConditional (FRIENDLY_NAME_ATTR, "");

            app_usage = AppUsage.getKeyUsageFromString (ah.getString (APP_USAGE_ATTR));

            private_key_backup = ah.getBooleanConditional (PRIVATE_KEY_BACKUP_ATTR);

            enable_pin_caching = ah.getBooleanConditional (ENABLE_PIN_CACHING_ATTR);
            
            endorsed_algorithms = ah.getListConditional (ENDORSED_ALGORITHMS_ATTR);
            if (endorsed_algorithms == null)
              {
                endorsed_algorithms = new String[0];
              }
            else
              {
                endorsed_algorithms = BasicCapabilities.getSortedAlgorithms (endorsed_algorithms);
              }

            server_seed = ah.getBinaryConditional (SERVER_SEED_ATTR);
            if (server_seed == null)
              {
                server_seed = SecureKeyStore.DEFAULT_SEED;
              }
            else if (server_seed.length != 32)
              {
                bad ("Sever seed must be 32 bytes");
              }

            biometric_protection = BiometricProtection.getBiometricProtectionFromString (ah.getStringConditional (BIOMETRIC_PROTECTION_ATTR, 
                                                                                         BiometricProtection.NONE.getXMLName ()));

            delete_protection = DeleteProtection.getDeletePolicyFromString (ah.getStringConditional (DELETE_PROTECTION_ATTR, 
                                                                            DeleteProtection.NONE.getXMLName ()));
            export_protection = ExportProtection.getExportPolicyFromString (ah.getStringConditional (EXPORT_PROTECTION_ATTR, 
                                                                            ExportProtection.NON_EXPORTABLE.getXMLName ()));

            rd.getChild ();

            if (rd.hasNext (RSA_ELEM))
              {
                rd.getNext (RSA_ELEM);
                key_specifier = new KeySpecifier.RSA (ah.getInt (KEY_SIZE_ATTR), ah.getIntConditional (EXPONENT_ATTR));
              }
            else
              {
                rd.getNext (EC_ELEM);
                String ec_uri = ah.getString (NAMED_CURVE_ATTR);
                if (ec_uri.startsWith ("urn:oid:"))
                  {
                    key_specifier = new KeySpecifier.EC (ECDomains.getECDomainFromOID (ec_uri.substring (8)));
                  }
                else
                  {
                    bad ("urn:oid: expected");
                  }
              }
            rd.getParent ();
          }


        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }


        public byte[] getPresetPIN ()
          {
            return preset_pin == null ? null : preset_pin.encrypted_value;
          }


        public boolean isStartOfPINPolicy ()
          {
            return start_of_pin_group;
          }


        public boolean isStartOfPUKPolicy ()
          {
            return start_of_puk_group;
          }


        public boolean isDevicePINProtected ()
          {
            return device_pin_protected;
          }


        public KeySpecifier getKeySpecifier ()
          {
            return key_specifier;
          }


        public AppUsage getAppUsage ()
          {
            return app_usage;
          }


        public String getID ()
          {
            return id;
          }

        
        public byte[] getMAC ()
          {
            return mac;
          }
        

        byte[] server_seed;
        
        public byte[] getServerSeed ()
          {
            return server_seed;
          }
        
        BiometricProtection biometric_protection;

        public BiometricProtection getBiometricProtection ()
          {
            return biometric_protection;
          }

        
        boolean private_key_backup;
        
        public boolean getPrivateKeyBackupFlag ()
          {
            return private_key_backup;
          }
        

        ExportProtection export_protection;
        
        public ExportProtection getExportProtection ()
          {
            return export_protection;
          }

        
        DeleteProtection delete_protection;
        
        public DeleteProtection getDeleteProtection ()
          {
            return delete_protection;
          }

        
        boolean enable_pin_caching;
        
        public boolean getEnablePINCachingFlag ()
          {
            return enable_pin_caching;
          }

      
        String friendly_name;
        
        public String getFriendlyName ()
          {
            return friendly_name;
          }
        
        
        String[] endorsed_algorithms;

        public String[] getEndorsedAlgorithms ()
          {
            return endorsed_algorithms;
          }

      }


    private void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    private KeyObject readKeyProperties (DOMReaderHelper rd,
                                         PINPolicy pin_policy,
                                         boolean start_of_pin_group) throws IOException
      {
        KeyObject rk;
        if (rd.hasNext (PRESET_PIN_ELEM))
          {
            rd.getNext (PRESET_PIN_ELEM);
            PresetPIN preset = new PresetPIN (rd);
            rd.getChild ();
            request_objects.add (rk = new KeyObject (rd, pin_policy, start_of_pin_group, preset, false));
            rd.getParent ();
          }
        else
          {
            if (pin_policy != null)
              {
                pin_policy.user_defined = true;
                if (!pin_policy.read_user_modifiable)
                  {
                    pin_policy.user_modifiable = true;
                  }
              }
            request_objects.add (rk = new KeyObject (rd, pin_policy, start_of_pin_group, null, false));
          }
        return rk;
      }
      

    private void readKeyProperties (DOMReaderHelper rd, boolean device_pin_protected) throws IOException
      {
        request_objects.add (new KeyObject (rd, null, false, null, device_pin_protected));
      }


    private void readPINPolicy (DOMReaderHelper rd, boolean puk_start, PUKPolicy puk_policy) throws IOException
      {
        boolean start = true;
        rd.getNext (PIN_POLICY_ELEM);
        PINPolicy upp = new PINPolicy (rd);
        upp.puk_policy = puk_policy;
        rd.getChild ();
        do
          {
            KeyObject rk = readKeyProperties (rd, upp, start);
            rk.start_of_puk_group = puk_start;
            puk_start = false;
            start = false;
          }
        while (rd.hasNext ());
        rd.getParent ();
      }


    private Vector<KeyObject> request_objects = new Vector<KeyObject> ();
      
    private String submit_url;

    private ServerCookie server_cookie;     // Optional

    private boolean deferred_certification;

    private XMLSignatureWrapper signature;  // Optional

    private String server_session_id;

    private String client_session_id;

    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }
    
    String algorithm;
    
    public String getAlgorithm ()
      {
        return algorithm;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public boolean getDeferredCertificationFlag ()
      {
        return deferred_certification;
      }


    public KeyObject[] getKeyObjects () throws IOException
      {
        return request_objects.toArray (new KeyObject[0]);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        deferred_certification = ah.getBooleanConditional (DEFERRED_CERTIFICATION_ATTR);

        algorithm = ah.getString (XMLSignatureWrapper.ALGORITHM_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the request and management elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
         while (true)
          {
            if (rd.hasNext (KEY_ENTRY_ELEM))
              {
                readKeyProperties (rd, false);
              }
            else if (rd.hasNext (PUK_POLICY_ELEM))
              {
                boolean start = true;
                rd.getNext (PUK_POLICY_ELEM);
                PUKPolicy pk = new PUKPolicy (rd);
                rd.getChild ();
                do
                  {
                    readPINPolicy (rd, start, pk);
                    start = false;
                  }
                while (rd.hasNext ());
                rd.getParent ();
              }
            else if (rd.hasNext (PIN_POLICY_ELEM))
              {
                readPINPolicy (rd, false, null);
              }
            else if (rd.hasNext (DEVICE_PIN_PROTECTION_ELEM))
              {
                rd.getNext (DEVICE_PIN_PROTECTION_ELEM);
                rd.getChild ();
                readKeyProperties (rd, true);
                rd.getParent ();
              }
            else break;
          }
 
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ()) // Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }

