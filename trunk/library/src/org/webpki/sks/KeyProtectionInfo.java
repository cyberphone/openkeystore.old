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
package org.webpki.sks;

import org.webpki.keygen2.PassphraseFormat;

public class KeyProtectionInfo
  {
    static final byte PROTECTION_STATUS_NO_PIN             = 0x00;
    static final byte PROTECTION_STATUS_PIN_PROTECTED      = 0x01;
    static final byte PROTECTION_STATUS_PIN_BLOCKED        = 0x04;
    static final byte PROTECTION_STATUS_PUK_PROTECTED      = 0x02;
    static final byte PROTECTION_STATUS_PUK_BLOCKED        = 0x08;
    static final byte PROTECTION_STATUS_DEVICE_PIN         = 0x10;

    boolean enable_pin_caching;
    
    byte protection_status;
    
    byte input_method;
    
    byte export_policy;
    
    byte delete_policy;
    
    public boolean getPINCachingFlag ()
      {
        return enable_pin_caching;
      }

    public byte getProtectionStatus ()
      {
        return protection_status;
      }
    
    public byte getInputMethod ()
      {
        return input_method;
      }

    public byte getExportPolicy ()
      {
        return export_policy;
      }

    public byte getDeletePolicy ()
      {
        return delete_policy;
      }
    
    public boolean isPINBlocked ()
      {
        return (protection_status & PROTECTION_STATUS_PIN_BLOCKED) != 0;
      }

    public boolean isPINProtected ()
      {
        return (protection_status & PROTECTION_STATUS_PIN_PROTECTED) != 0;
      }

    public boolean isPUKProtected ()
      {
        return (protection_status & PROTECTION_STATUS_PUK_PROTECTED) != 0;
      }
    
    PassphraseFormat format;
    
    public PassphraseFormat getPINFormat () throws SKSException
      {
        return format;
      }

    PassphraseFormat puk_format;
    
    public PassphraseFormat getPUKFormat () throws SKSException
      {
        return puk_format;
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
                              byte biometric_protection,
                              boolean private_key_backup,
                              byte export_policy,
                              byte delete_policy,
                              boolean enable_pin_caching) throws SKSException

      {
        this.protection_status = protection_status;
        if (isPUKProtected ())
          {
            this.puk_format = convertFormat (puk_format);
          }
        if (isPINProtected ())
          {
            this.format = convertFormat (format);
          }
        this.enable_pin_caching = enable_pin_caching;
        this.input_method = input_method;
        this.export_policy = export_policy;
        this.delete_policy = delete_policy;
      }
  }
