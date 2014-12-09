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
package org.webpki.sks;


import java.util.EnumSet;
import java.util.Set;

public class KeyProtectionInfo
  {
    ///////////////////////////////////////////////////////////////////////////////////
    // "ProtectionStatus" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte PROTSTAT_NO_PIN             = 0x00;
    public static final byte PROTSTAT_PIN_PROTECTED      = 0x01;
    public static final byte PROTSTAT_PIN_BLOCKED        = 0x04;
    public static final byte PROTSTAT_PUK_PROTECTED      = 0x02;
    public static final byte PROTSTAT_PUK_BLOCKED        = 0x08;
    public static final byte PROTSTAT_DEVICE_PIN         = 0x10;

    ///////////////////////////////////////////////////////////////////////////////////
    // "KeyBackup" bit-field constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte KEYBACKUP_IMPORTED          = 0x01;
    public static final byte KEYBACKUP_EXPORTED          = 0x02;
 
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
    
    private byte key_backup;
    
    private ExportProtection export_protection;
    
    private DeleteProtection delete_protection;
    
    public byte getSKSProtectionStatus ()
      {
        return protection_status;
      }

    public boolean hasLocalPukProtection ()
      {
        return (protection_status & PROTSTAT_PUK_PROTECTED) != 0;
      }
    
    public PassphraseFormat getPukFormat () throws SKSException
      {
        return puk_format;
      }

    public short getPukErrorCount ()
      {
        return puk_error_count;
      }

    public short getPukRetryLimit ()
      {
        return puk_retry_limit;
      }

    public boolean isPukBlocked ()
      {
        return (protection_status & PROTSTAT_PUK_BLOCKED) != 0;
      }

    public boolean hasLocalPinProtection ()
      {
        return (protection_status & PROTSTAT_PIN_PROTECTED) != 0;
      }

    public PassphraseFormat getPinFormat () throws SKSException
      {
        return pin_format;
      }

    public Grouping getPinGrouping () throws SKSException
      {
        return pin_grouping;
      }

    public short getPinMinLength ()
      {
        return pin_min_length;
      }

    public short getPinMaxLength ()
      {
        return pin_max_length;
      }

    public boolean getPinUserModifiableFlag ()
      {
        return pin_user_modifiable;
      }

    public boolean getPinUserDefinedFlag ()
      {
        return pin_user_defined;
      }

    public InputMethod getPinInputMethod ()
      {
        return pin_input_method;
      }

    public boolean isPinBlocked ()
      {
        return (protection_status & PROTSTAT_PIN_BLOCKED) != 0;
      }

    public boolean hasDevicePinProtection ()
      {
        return (protection_status & PROTSTAT_DEVICE_PIN) != 0;
      }

    public short getPinErrorCount ()
      {
        return pin_error_count;
      }

    public short getPinRetryLimit ()
      {
        return pin_retry_limit;
      }
    
    public Set<PatternRestriction> getPatternRestrictions ()
      {
        return pin_pattern_restrictions;
      }

    public BiometricProtection getBiometricProtection ()
      {
        return biometric_protection;
      }

    public byte getKeyBackup ()
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
    
    public boolean getEnablePinCachingFlag ()
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
                              byte puk_format,
                              short puk_retry_limit,
                              short puk_error_count,
                              boolean user_defined,
                              boolean user_modifiable,
                              byte format,
                              short retry_limit,
                              byte grouping,
                              byte pattern_restrictions,
                              short min_length,
                              short max_length,
                              byte input_method,
                              short pin_error_count,
                              boolean enable_pin_caching,
                              byte biometric_protection,
                              byte export_protection,
                              byte delete_protection,
                              byte key_backup) throws SKSException

      {
        this.protection_status = protection_status;
        if (hasLocalPukProtection ())
          {
            this.puk_format = convertFormat (puk_format);
            this.puk_error_count = puk_error_count;
            this.puk_retry_limit = puk_retry_limit;
          }
        if (hasLocalPinProtection ())
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
        if (hasLocalPinProtection () || hasDevicePinProtection ())
          {
            this.enable_pin_caching = enable_pin_caching;
          }
        this.key_backup = key_backup;
        this.biometric_protection = convertBiometricProtection (biometric_protection);
        this.export_protection = convertExportProtection (export_protection);
        this.delete_protection = convertDeleteProtection (delete_protection);
      }
  }
