/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;


    abstract class PresetValueReference
      {
        byte[] encrypted_value;

        PresetValueReference (JSONObjectReader rd, String name_of_key) throws IOException
          {
            encrypted_value = getEncryptedKey (rd, name_of_key);
          }
        
        public byte[] getEncryptedValue ()
          {
            return encrypted_value;
          }
      }


    public class PresetPIN extends PresetValueReference
      {
        boolean user_modifiable;

        PresetPIN (JSONObjectReader rd, String name_of_key) throws IOException
          {
            super (rd, name_of_key);
            user_modifiable = rd.getBooleanConditional (USER_MODIFIABLE_JSON);
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
 
        PUKPolicy (JSONObjectReader rd) throws IOException
          {
            super (rd, ENCRYPTED_PUK_JSON);
            retry_limit = getAuthorizationRetryLimit (rd, 0);
            id = KeyGen2Validator.getID (rd, ID_JSON);
            format = getPassphraseFormat (rd);
            mac = rd.getBinary (MAC_JSON);
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

        short min_length;

        short max_length;

        Grouping grouping;

        InputMethod input_method;

        Set<PatternRestriction> pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);

        PINPolicy (JSONObjectReader rd) throws IOException
          {
            mac = rd.getBinary (MAC_JSON);
            
            id = KeyGen2Validator.getID (rd, ID_JSON);

            min_length = getPINLength (rd, MIN_LENGTH_JSON);

            max_length = getPINLength (rd, MAX_LENGTH_JSON);

            if (min_length > max_length)
              {
                bad ("PIN length: min > max");
              }

            retry_limit = getAuthorizationRetryLimit (rd, 1);

            format = getPassphraseFormat (rd);

            grouping = Grouping.getGroupingFromString (rd.getStringConditional (GROUPING_JSON, Grouping.NONE.getProtocolName ()));

            input_method = InputMethod.getInputMethodFromString (rd.getStringConditional (INPUT_METHOD_JSON, InputMethod.ANY.getProtocolName ()));
            
            read_user_modifiable = rd.hasProperty (USER_MODIFIABLE_JSON);
            user_modifiable = rd.getBooleanConditional (USER_MODIFIABLE_JSON, false);

            String pr[] = rd.getStringArrayConditional (PATTERN_RESTRICTIONS_JSON);
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


        public short getMinLength ()
          {
            return min_length;
          }


        public short getMaxLength ()
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
            return grouping;
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

        byte[] user_set_pin;

        boolean device_pin_protected;
        
        AppUsage app_usage;

        KeySpecifier key_specifier;
        
        KeyObject (JSONObjectReader rd, 
                   PINPolicy pin_policy,
                   boolean start_of_pin_group, 
                   PresetPIN preset_pin,
                   boolean device_pin_protected) throws IOException
          {
            this.pin_policy = pin_policy;
            this.start_of_pin_group = start_of_pin_group;
            this.preset_pin = preset_pin;
            this.device_pin_protected = device_pin_protected;

            id = KeyGen2Validator.getID (rd, ID_JSON);

            key_specifier = new KeySpecifier (getURI (rd, KEY_ALGORITHM_JSON),
                                              rd.getBinaryConditional (KEY_PARAMETERS_JSON));

            if (rd.hasProperty (ENDORSED_ALGORITHMS_JSON))
              {
                endorsed_algorithms = BasicCapabilities.getSortedAlgorithms (getURIList (rd, ENDORSED_ALGORITHMS_JSON));
              }
            else
              {
                endorsed_algorithms = new String[0];
              }

            server_seed = rd.getBinaryConditional (SERVER_SEED_JSON);

            app_usage = AppUsage.getAppUsageFromString (rd.getString (APP_USAGE_JSON));

            enable_pin_caching = rd.getBooleanConditional (ENABLE_PIN_CACHING_JSON);
            
            biometric_protection = BiometricProtection.getBiometricProtectionFromString (rd.getStringConditional (BIOMETRIC_PROTECTION_JSON, 
                                                                                         BiometricProtection.NONE.getProtocolName ()));

            delete_protection = DeleteProtection.getDeletePolicyFromString (rd.getStringConditional (DELETE_PROTECTION_JSON, 
                                                                            DeleteProtection.NONE.getProtocolName ()));

            export_protection = ExportProtection.getExportPolicyFromString (rd.getStringConditional (EXPORT_PROTECTION_JSON, 
                                                                            ExportProtection.NON_EXPORTABLE.getProtocolName ()));

            friendly_name = rd.getStringConditional (FRIENDLY_NAME_JSON);

            mac = rd.getBinary (MAC_JSON);
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

        
        public byte[] getSKSPINValue ()
          {
            return user_set_pin == null ? getPresetPIN () : user_set_pin;
          }
      }

    public class UserPINError
      {
        public boolean length_error;
        public boolean syntax_error;
        public boolean unique_error;
        public AppUsage unique_error_app_usage;
        public PatternRestriction pattern_error;
      }
    

    public class UserPINDescriptor
      {
        PINPolicy pin_policy;
        AppUsage app_usage;
        
        private UserPINDescriptor (PINPolicy pin_policy, AppUsage app_usage)
          {
            this.pin_policy = pin_policy;
            this.app_usage = app_usage;
          }

        public PINPolicy getPINPolicy ()
          {
            return pin_policy;
          }

        public AppUsage getAppUsage ()
          {
            return app_usage;
          }
        
        public UserPINError setPIN (String pin_string_value, boolean set_value_on_success)
          {
            UserPINError error = new UserPINError ();

            byte[] pin = null;
            try
              {
                if (pin_string_value.length () > 0 && pin_policy.format == PassphraseFormat.BINARY)
                  {
                    pin = DebugFormatter.getByteArrayFromHex (pin_string_value);
                  }
                else
                  {
                    pin = pin_string_value.getBytes ("UTF-8");
                  }
              }
            catch (IOException e)
              {
                error.syntax_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN length
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_policy.min_length > pin.length || pin_policy.max_length < pin.length)
              {
                error.length_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN syntax
            ///////////////////////////////////////////////////////////////////////////////////
            boolean upperalpha = false;
            boolean loweralpha = false;
            boolean number = false;
            boolean nonalphanum = false;
            for (int i = 0; i < pin.length; i++)
              {
                int c = pin[i];
                if (c >= 'A' && c <= 'Z')
                  {
                    upperalpha = true;
                  }
                else if (c >= 'a' && c <= 'z')
                  {
                    loweralpha = true;
                  }
                else if (c >= '0' && c <= '9')
                  {
                    number = true;
                  }
                else
                  {
                    nonalphanum = true;
                  }
              }
            if ((pin_policy.format == PassphraseFormat.NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
                (pin_policy.format == PassphraseFormat.ALPHANUMERIC && (loweralpha || nonalphanum)))
              {
                error.syntax_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN patterns
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_policy.pattern_restrictions.contains (PatternRestriction.MISSING_GROUP))
              {
                if (!upperalpha || !number ||
                    (pin_policy.format == PassphraseFormat.STRING && (!loweralpha || !nonalphanum)))
                  {
                    error.pattern_error = PatternRestriction.MISSING_GROUP;
                    return error;
                  }
              }
            if (pin_policy.pattern_restrictions.contains (PatternRestriction.SEQUENCE))
              {
                byte c = pin[0];
                byte f = (byte)(pin[1] - c);
                boolean seq = (f == 1) || (f == -1);
                for (int i = 1; i < pin.length; i++)
                  {
                    if ((byte)(c + f) != pin[i])
                      {
                        seq = false;
                        break;
                      }
                    c = pin[i];
                  }
                if (seq)
                  {
                    error.pattern_error = PatternRestriction.SEQUENCE;
                    return error;
                  }
              }
            if (pin_policy.pattern_restrictions.contains (PatternRestriction.REPEATED))
              {
                for (int i = 0; i < pin.length; i++)
                  {
                    byte b = pin[i];
                    for (int j = 0; j < pin.length; j++)
                      {
                        if (j != i && b == pin[j])
                          {
                            error.pattern_error = PatternRestriction.REPEATED;
                            return error;
                          }
                      }
                  }
              }
            if (pin_policy.pattern_restrictions.contains (PatternRestriction.TWO_IN_A_ROW) ||
                pin_policy.pattern_restrictions.contains (PatternRestriction.THREE_IN_A_ROW))
              {
                int max = pin_policy.pattern_restrictions.contains (PatternRestriction.THREE_IN_A_ROW) ? 3 : 2;
                byte c = pin [0];
                int same_count = 1;
                for (int i = 1; i < pin.length; i++)
                  {
                    if (c == pin[i])
                      {
                        if (++same_count == max)
                          {
                            error.pattern_error = max == 2 ? PatternRestriction.TWO_IN_A_ROW : PatternRestriction.THREE_IN_A_ROW;
                            return error;
                          }
                      }
                    else
                      {
                        same_count = 1;
                        c = pin[i];
                      }
                  }
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check that PIN grouping rules are followed
            ///////////////////////////////////////////////////////////////////////////////////
            Vector<KeyObject> keys_needing_pin = new Vector<KeyObject> ();
            for (KeyObject key : request_objects)
              {
                if (key.pin_policy == pin_policy)
                  {
                    switch (pin_policy.grouping)
                      {
                        case NONE:
                          if (key.user_set_pin == null)
                            {
                              keys_needing_pin.add (key);
                              break;
                            }
                          continue;
 
                        case SHARED:
                          keys_needing_pin.add (key);
                          continue;
                  
                        case UNIQUE:
                          if (app_usage == key.app_usage)
                            {
                              keys_needing_pin.add (key);
                            }
                          else
                            {
                              if (key.user_set_pin != null && ArrayUtil.compare (pin, key.user_set_pin))
                                {
                                  error.unique_error = true;
                                  error.unique_error_app_usage = key.app_usage;
                                  return error;
                                }
                            }
                          continue;

                        case SIGNATURE_PLUS_STANDARD:
                          if ((app_usage == AppUsage.SIGNATURE) ^ (key.app_usage == AppUsage.SIGNATURE))
                            {
                              if (key.user_set_pin != null && ArrayUtil.compare (pin, key.user_set_pin))
                                {
                                  error.unique_error = true;
                                  error.unique_error_app_usage = key.app_usage;
                                  return error;
                                }
                            }
                          else
                            {
                              keys_needing_pin.add (key);
                            }
                          continue;
                      }
                    break;
                  }
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // We did it!  Assign the PIN to the associated keys or just return null=success
            ///////////////////////////////////////////////////////////////////////////////////
            if (set_value_on_success)
              {
                for (KeyObject key : keys_needing_pin)
                  {
                    key.user_set_pin = pin;
                  }
              }
            return null;
          }
      }


    public Vector<KeyObject> getKeyObjects () throws IOException
      {
        return request_objects;
      }


    public Vector<UserPINDescriptor> getUserPINDescriptors ()
      {
        Vector<UserPINDescriptor> user_pin_policies = new Vector<UserPINDescriptor>();
        for (KeyObject key: request_objects)
          {
            if (key.getPINPolicy () != null && key.getPINPolicy ().getUserDefinedFlag ())
              {
                UserPINDescriptor pin_desc = new UserPINDescriptor (key.pin_policy, key.app_usage);
                if (key.pin_policy.grouping == Grouping.NONE)
                  {
                    user_pin_policies.add (pin_desc);
                  }
                else 
                  {
                    for (UserPINDescriptor upd2 : user_pin_policies)
                      {
                        if (upd2.pin_policy == key.pin_policy)
                          {
                            if (key.pin_policy.grouping == Grouping.SHARED)
                              {
                                pin_desc = null;
                                break;
                              }
                            if (key.pin_policy.grouping == Grouping.UNIQUE)
                              {
                                if (upd2.app_usage == key.app_usage)
                                  {
                                    pin_desc = null;
                                    break;
                                  }
                              }
                            else
                              {
                                if ((upd2.app_usage == AppUsage.SIGNATURE) ^ (key.app_usage != AppUsage.SIGNATURE))
                                  {
                                    pin_desc = null;
                                    break;
                                  }
                              }
                          }
                      }
                    if (pin_desc != null)
                      {
                        user_pin_policies.add (pin_desc);
                      }
                  }
              }
          }
        return user_pin_policies;
      }

    
    private KeyObject readKeyProperties (JSONObjectReader rd,
                                         PINPolicy pin_policy,
                                         boolean start_of_pin_group) throws IOException
      {
        KeyObject rk;
        PresetPIN preset = null;
        if (rd.hasProperty (ENCRYPTED_PRESET_PIN_JSON))
          {
            preset = new PresetPIN (rd, ENCRYPTED_PRESET_PIN_JSON);
          }
        else
          {
            pin_policy.user_defined = true;
          }
        if (!pin_policy.read_user_modifiable)
          {
            pin_policy.user_modifiable = true;
          }
        request_objects.add (rk = new KeyObject (rd, pin_policy, start_of_pin_group, preset, false));
        return rk;
      }
      

    private void readKeyProperties (JSONObjectReader rd, boolean device_pin_protected) throws IOException
      {
        request_objects.add (new KeyObject (rd, null, false, null, device_pin_protected));
      }


    private PassphraseFormat getPassphraseFormat (JSONObjectReader rd) throws IOException
      {
        return PassphraseFormat.getPassphraseFormatFromString (rd.getString (FORMAT_JSON));
      }


    private Vector<KeyObject> request_objects = new Vector<KeyObject> ();
      
    private String submit_url;

    private boolean deferred_certification;

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


    
    String algorithm;
    
    public String getAlgorithm ()
      {
        return algorithm;
      }


    public boolean getDeferredCertificationFlag ()
      {
        return deferred_certification;
      }

    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, CLIENT_SESSION_ID_JSON);

        submit_url = getURL (rd, SUBMIT_URL_JSON);

        deferred_certification = rd.getBooleanConditional (DEFERRED_CERTIFICATION_JSON);

        algorithm = getURI (rd, KEY_ENTRY_ALGORITHM_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the key requests and protection elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader puk : getObjectArrayConditional (rd, PUK_POLICY_SPECIFIERS_JSON))
          {
            readPINProtectedKeys (puk, new PUKPolicy (puk));
          }
        if (rd.hasProperty (PIN_POLICY_SPECIFIERS_JSON))
          {
            readPINProtectedKeys (rd, null);
          }
        for (JSONObjectReader key : getObjectArrayConditional (rd, KEY_ENTRY_SPECIFIERS_JSON))
          {
            readKeyProperties (key, key.getBooleanConditional (DEVICE_PIN_PROTECTION_JSON));
          }
      }

    void readPINProtectedKeys (JSONObjectReader rd, PUKPolicy puk_policy) throws IOException
      {
        boolean startofpuk = puk_policy != null;
        for (JSONObjectReader pin : getObjectArray (rd, PIN_POLICY_SPECIFIERS_JSON))
          {
            PINPolicy pin_policy = new PINPolicy (pin);
            pin_policy.puk_policy = puk_policy;
            boolean start = true;
            for (JSONObjectReader key : getObjectArray (pin, KEY_ENTRY_SPECIFIERS_JSON))
              {
                readKeyProperties (key, pin_policy, start).start_of_puk_group = startofpuk;
                start = false;
                startofpuk = false;
              }
          }
      }


    @Override
    public String getQualifier ()
      {
        return KEY_CREATION_REQUEST_JSON;
      }
  }
