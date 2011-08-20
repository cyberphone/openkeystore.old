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
package org.webpki.sks;


import java.util.EnumSet;
import java.util.Set;

import static org.webpki.sks.SecureKeyStore.*;

public class KeyProtectionInfo
  {
    private PassphraseFormat puk_format;
    
    private short puk_error_count;
    
    private short puk_retry_limit;
    
    private boolean enable_pin_caching;
    
    private boolean pin_user_defined;

    private boolean pin_user_modifiable;
    
    private byte protection_status;
    
    private short pin_min_length;

    private short pin_max_length;

    private InputMethod pin_input_method;
    
    private short pin_retry_limit;
    
    private Grouping pin_grouping;
    
    private Set<PatternRestriction> pin_pattern_restrictions;
    
    private PassphraseFormat pin_format;
    
    private short pin_error_count;
    
    private BiometricProtection biometric_protection;
    
    private boolean key_backup;
    
    private ExportProtection export_protection;
    
    private DeleteProtection delete_protection;
    
    public byte getSKSProtectionStatus ()
      {
        return protection_status;
      }

    public boolean hasLocalPUKProtection ()
      {
        return (protection_status & PROTECTION_STATUS_PUK_PROTECTED) != 0;
      }
    
    public PassphraseFormat getPUKFormat () throws SKSException
      {
        return puk_format;
      }

    public short getPUKErrorCount ()
      {
        return puk_error_count;
      }

    public short getPUKRetryLimit ()
      {
        return puk_retry_limit;
      }

    public boolean isPUKBlocked ()
      {
        return (protection_status & PROTECTION_STATUS_PUK_BLOCKED) != 0;
      }

    public boolean hasLocalPINProtection ()
      {
        return (protection_status & PROTECTION_STATUS_PIN_PROTECTED) != 0;
      }

    public PassphraseFormat getPINFormat () throws SKSException
      {
        return pin_format;
      }

    public Grouping getPINGrouping () throws SKSException
      {
        return pin_grouping;
      }

    public short getPINMinLength ()
      {
        return pin_min_length;
      }

    public short getPINMaxLength ()
      {
        return pin_max_length;
      }

    public boolean getPINUserModifiableFlag ()
      {
        return pin_user_modifiable;
      }

    public boolean getPINUserDefinedFlag ()
      {
        return pin_user_defined;
      }

    public InputMethod getPINInputMethod ()
      {
        return pin_input_method;
      }

    public boolean isPINBlocked ()
      {
        return (protection_status & PROTECTION_STATUS_PIN_BLOCKED) != 0;
      }

    public boolean hasDevicePINProtection ()
      {
        return (protection_status & PROTECTION_STATUS_DEVICE_PIN) != 0;
      }

    public short getPINErrorCount ()
      {
        return pin_error_count;
      }

    public short getPINRetryLimit ()
      {
        return pin_retry_limit;
      }
    
    public Set<PatternRestriction> getPINPatternRestrictions ()
      {
        return pin_pattern_restrictions;
      }

    public BiometricProtection getBiometricProtection ()
      {
        return biometric_protection;
      }

    public boolean getKeyBackupFlag ()
      {
        return key_backup;
      }

    public ExportProtection getExportProtection ()
      {
        return export_protection;
      }

    public DeleteProtection getDeleteProtection ()
      {
        return delete_protection;
      }
    
    public boolean getEnablePINCachingFlag ()
      {
        return enable_pin_caching;
      }

    private PassphraseFormat convertFormat (byte format) throws SKSException
      {
        for (PassphraseFormat kg2_format : PassphraseFormat.values ())
          {
            if (kg2_format.getSKSValue () == format)
              {
                return kg2_format;
              }
          }
        throw new SKSException ("Unknown format: " + format);
      }
    
    private InputMethod convertInputMethod (byte input_method) throws SKSException
      {
        for (InputMethod kg2_input_method : InputMethod.values ())
          {
            if (kg2_input_method.getSKSValue () == input_method)
              {
                return kg2_input_method;
              }
          }
        throw new SKSException ("Unknown input method: " + input_method);
      }

    private ExportProtection convertExportProtection (byte export_protection) throws SKSException
      {
        for (ExportProtection kg2_export_protection : ExportProtection.values ())
          {
            if (kg2_export_protection.getSKSValue () == export_protection)
              {
                return kg2_export_protection;
              }
          }
        throw new SKSException ("Unknown export protection: " + export_protection);
      }

    private DeleteProtection convertDeleteProtection (byte delete_protection) throws SKSException
      {
        for (DeleteProtection kg2_delete_protection : DeleteProtection.values ())
          {
            if (kg2_delete_protection.getSKSValue () == delete_protection)
              {
                return kg2_delete_protection;
              }
          }
        throw new SKSException ("Unknown delete protection: " + delete_protection);
      }

    private Grouping convertGrouping (byte grouping) throws SKSException
      {
        for (Grouping kg2_grouping : Grouping.values ())
          {
            if (kg2_grouping.getSKSValue () == grouping)
              {
                return kg2_grouping;
              }
          }
        throw new SKSException ("Unknown grouping: " + grouping);
      }

    private BiometricProtection convertBiometricProtection (byte biometric_protection) throws SKSException
      {
        for (BiometricProtection kg2_biometric_protection : BiometricProtection.values ())
          {
            if (kg2_biometric_protection.getSKSValue () == biometric_protection)
              {
                return kg2_biometric_protection;
              }
          }
        throw new SKSException ("Unknown biometric protection: " + biometric_protection);
      }

    public KeyProtectionInfo (byte protection_status,
                              Byte puk_format,
                              Short puk_retry_limit,
                              Short puk_error_count,
                              Boolean user_defined,
                              Boolean user_modifiable,
                              Byte format,
                              Short retry_limit,
                              Byte grouping,
                              Byte pattern_restrictions,
                              Short min_length,
                              Short max_length,
                              Byte input_method,
                              Short pin_error_count,
                              Boolean enable_pin_caching,
                              byte biometric_protection,
                              byte export_protection,
                              byte delete_protection,
                              boolean key_backup) throws SKSException

      {
        this.protection_status = protection_status;
        if (hasLocalPUKProtection ())
          {
            this.puk_format = convertFormat (puk_format);
            this.puk_error_count = puk_error_count;
            this.puk_retry_limit = puk_retry_limit;
          }
        if (hasLocalPINProtection ())
          {
            this.pin_user_defined = user_defined;
            this.pin_user_modifiable = user_modifiable;
            this.pin_format = convertFormat (format);
            this.pin_retry_limit = retry_limit;
            this.pin_grouping = convertGrouping (grouping);
            this.pin_pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);
            for (PatternRestriction pattern : PatternRestriction.values ())
              {
                if ((pattern.getSKSMaskBit () & pattern_restrictions) != 0)
                  {
                    this.pin_pattern_restrictions.add (pattern);
                  }
              }
            this.pin_min_length = min_length;
            this.pin_max_length = max_length;
            this.pin_input_method = convertInputMethod (input_method);
            this.pin_error_count = pin_error_count;
          }
        if (hasLocalPINProtection () || hasDevicePINProtection ())
          {
            this.enable_pin_caching = enable_pin_caching;
          }
        this.key_backup = key_backup;
        this.biometric_protection = convertBiometricProtection (biometric_protection);
        this.export_protection = convertExportProtection (export_protection);
        this.delete_protection = convertDeleteProtection (delete_protection);
      }
  }
