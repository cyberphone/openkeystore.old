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
 
    private PassphraseFormat pukFormat;
    
    private short pukErrorCount;
    
    private short pukRetryLimit;
    
    private boolean enablePinCaching;
    
    private boolean pinUserDefined;

    private boolean pinUserModifiable;
    
    private byte protectionStatus;
    
    private short pinMinLength;

    private short pinMaxLength;

    private InputMethod pinInputMethod;
    
    private short pinRetryLimit;
    
    private Grouping pinGrouping;
    
    private Set<PatternRestriction> pinPatternRestrictions;
    
    private PassphraseFormat pinFormat;
    
    private short pinErrorCount;
    
    private BiometricProtection biometricProtection;
    
    private byte keyBackup;
    
    private ExportProtection exportProtection;
    
    private DeleteProtection deleteProtection;
    
    public byte getSKSProtectionStatus ()
      {
        return protectionStatus;
      }

    public boolean hasLocalPukProtection ()
      {
        return (protectionStatus & PROTSTAT_PUK_PROTECTED) != 0;
      }
    
    public PassphraseFormat getPukFormat () throws SKSException
      {
        return pukFormat;
      }

    public short getPukErrorCount ()
      {
        return pukErrorCount;
      }

    public short getPukRetryLimit ()
      {
        return pukRetryLimit;
      }

    public boolean isPukBlocked ()
      {
        return (protectionStatus & PROTSTAT_PUK_BLOCKED) != 0;
      }

    public boolean hasLocalPinProtection ()
      {
        return (protectionStatus & PROTSTAT_PIN_PROTECTED) != 0;
      }

    public PassphraseFormat getPinFormat () throws SKSException
      {
        return pinFormat;
      }

    public Grouping getPinGrouping () throws SKSException
      {
        return pinGrouping;
      }

    public short getPinMinLength ()
      {
        return pinMinLength;
      }

    public short getPinMaxLength ()
      {
        return pinMaxLength;
      }

    public boolean getPinUserModifiableFlag ()
      {
        return pinUserModifiable;
      }

    public boolean getPinUserDefinedFlag ()
      {
        return pinUserDefined;
      }

    public InputMethod getPinInputMethod ()
      {
        return pinInputMethod;
      }

    public boolean isPinBlocked ()
      {
        return (protectionStatus & PROTSTAT_PIN_BLOCKED) != 0;
      }

    public boolean hasDevicePinProtection ()
      {
        return (protectionStatus & PROTSTAT_DEVICE_PIN) != 0;
      }

    public short getPinErrorCount ()
      {
        return pinErrorCount;
      }

    public short getPinRetryLimit ()
      {
        return pinRetryLimit;
      }
    
    public Set<PatternRestriction> getPatternRestrictions ()
      {
        return pinPatternRestrictions;
      }

    public BiometricProtection getBiometricProtection ()
      {
        return biometricProtection;
      }

    public byte getKeyBackup ()
      {
        return keyBackup;
      }

    public ExportProtection getExportProtection ()
      {
        return exportProtection;
      }

    public DeleteProtection getDeleteProtection ()
      {
        return deleteProtection;
      }
    
    public boolean getEnablePinCachingFlag ()
      {
        return enablePinCaching;
      }

    private PassphraseFormat convertFormat (byte format) throws SKSException
      {
        for (PassphraseFormat kg2_format : PassphraseFormat.values ())
          {
            if (kg2_format.getSksValue () == format)
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
            if (kg2_input_method.getSksValue () == input_method)
              {
                return kg2_input_method;
              }
          }
        throw new SKSException ("Unknown input method: " + input_method);
      }

    private ExportProtection convertExportProtection (byte exportProtection) throws SKSException
      {
        for (ExportProtection kg2_exportProtection : ExportProtection.values ())
          {
            if (kg2_exportProtection.getSksValue () == exportProtection)
              {
                return kg2_exportProtection;
              }
          }
        throw new SKSException ("Unknown export protection: " + exportProtection);
      }

    private DeleteProtection convertDeleteProtection (byte deleteProtection) throws SKSException
      {
        for (DeleteProtection kg2_deleteProtection : DeleteProtection.values ())
          {
            if (kg2_deleteProtection.getSksValue () == deleteProtection)
              {
                return kg2_deleteProtection;
              }
          }
        throw new SKSException ("Unknown delete protection: " + deleteProtection);
      }

    private Grouping convertGrouping (byte grouping) throws SKSException
      {
        for (Grouping kg2_grouping : Grouping.values ())
          {
            if (kg2_grouping.getSksValue () == grouping)
              {
                return kg2_grouping;
              }
          }
        throw new SKSException ("Unknown grouping: " + grouping);
      }

    private BiometricProtection convertBiometricProtection (byte biometricProtection) throws SKSException
      {
        for (BiometricProtection kg2_biometricProtection : BiometricProtection.values ())
          {
            if (kg2_biometricProtection.getSksValue () == biometricProtection)
              {
                return kg2_biometricProtection;
              }
          }
        throw new SKSException ("Unknown biometric protection: " + biometricProtection);
      }

    public KeyProtectionInfo (byte protectionStatus,
                              byte pukFormat,
                              short pukRetryLimit,
                              short pukErrorCount,
                              boolean userDefined,
                              boolean userModifiable,
                              byte format,
                              short retryLimit,
                              byte grouping,
                              byte patternRestrictions,
                              short minLength,
                              short maxLength,
                              byte input_method,
                              short pinErrorCount,
                              boolean enablePinCaching,
                              byte biometricProtection,
                              byte exportProtection,
                              byte deleteProtection,
                              byte keyBackup) throws SKSException

      {
        this.protectionStatus = protectionStatus;
        if (hasLocalPukProtection ())
          {
            this.pukFormat = convertFormat (pukFormat);
            this.pukErrorCount = pukErrorCount;
            this.pukRetryLimit = pukRetryLimit;
          }
        if (hasLocalPinProtection ())
          {
            this.pinUserDefined = userDefined;
            this.pinUserModifiable = userModifiable;
            this.pinFormat = convertFormat (format);
            this.pinRetryLimit = retryLimit;
            this.pinGrouping = convertGrouping (grouping);
            this.pinPatternRestrictions = EnumSet.noneOf (PatternRestriction.class);
            for (PatternRestriction pattern : PatternRestriction.values ())
              {
                if ((pattern.getSKSMaskBit () & patternRestrictions) != 0)
                  {
                    this.pinPatternRestrictions.add (pattern);
                  }
              }
            this.pinMinLength = minLength;
            this.pinMaxLength = maxLength;
            this.pinInputMethod = convertInputMethod (input_method);
            this.pinErrorCount = pinErrorCount;
          }
        if (hasLocalPinProtection () || hasDevicePinProtection ())
          {
            this.enablePinCaching = enablePinCaching;
          }
        this.keyBackup = keyBackup;
        this.biometricProtection = convertBiometricProtection (biometricProtection);
        this.exportProtection = convertExportProtection (exportProtection);
        this.deleteProtection = convertDeleteProtection (deleteProtection);
      }
  }
