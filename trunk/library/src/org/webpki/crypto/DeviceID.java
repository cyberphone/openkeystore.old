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
package org.webpki.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

/**
 * Device ID generator.
 * <p>A Device ID is a cryptographically secured 36-character identifier where the last
 * 4 characters represent a (SHA1-based) checksum of the 160-bit SHA1 hash of the
 * argument which is the actual identity.  The latter may be an IMEI-code, Device
 * Certificate, Apple-ID etc.</p>
 * 
 * <p>The checksum makes it easy verifying that the user has typed in the correct Device ID.</p>
 * 
 * <p>To further reduce mistakes the character-set has been limited to 32 visually
 * distinguishable characters:<pre>
 *     ABCDEFGHJKLMNPQRSTUVWXYZ23456789</pre></p>
 * 
 * <p>A user-display would typically show a Device ID like the following: <pre>
 *     CCCC-CCCC-CCCC-CCCC
 *     CCCC-CCCC-CCCC-CCCC
 *     CCCC</pre></p>
 */
public class DeviceID
  {
    private DeviceID () {}  // No instantiation
    
    private static final char[] MODIFIED_BASE32 = {'A','B','C','D','E','F','G','H',
                                                   'J','K','L','M','N','P','Q','R',
                                                   'S','T','U','V','W','X','Y','Z',
                                                   '2','3','4','5','6','7','8','9'};

    private static byte[] half (byte[] data)
      {
        if (data.length == 5)
          {
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            baos.write (data, 0, 2);
            byte rnibble = 0;
            byte lnibble = (byte)(data[2] & 0xF0);
            for (int i = 2; i < 5; i++)
              {
                baos.write ((byte)(lnibble | rnibble));
                lnibble = (byte)((data[i] & 0xF) << 4);
                if (i < 4)
                  {
                    rnibble = (byte)((data[i + 1] & 0xF0) >> 4);
                  }
              }
            baos.write (lnibble);
            data = baos.toByteArray ();
          }
        int offset = data.length / 2;
        byte[] result = new byte[offset];
        for (int i = 0; i < offset; i++)
          {
            result[i] = (byte)(data[i] ^ data[i + offset]);
          }
        return result;
      }
    
    public static String getDeviceID (byte[] identity_blob_or_null, char optional_divider)
      {
        if (identity_blob_or_null != null)
          {
            try
              {
                byte[] sha1 = HashAlgorithms.SHA1.digest (identity_blob_or_null);
                ByteArrayOutputStream baos = new ByteArrayOutputStream ();
                baos.write (sha1);
                baos.write (half (half (half (sha1))));
                byte[] data = baos.toByteArray ();
                StringBuffer buffer = new StringBuffer ();
                for (int bit_position = 0; bit_position < 180; bit_position += 5)
                  {
                    if (bit_position > 0 && bit_position % 20 == 0 && optional_divider != 0)
                      {
                        buffer.append (optional_divider);
                      }
                    int bit_position_in_byte = bit_position % 8;
                    int index = bit_position / 8;
                    byte value = (byte)(bit_position_in_byte > 3 
                                 ?
           ((data[index] << (bit_position_in_byte - 3)) & 0x1F) | ((data[index + 1] & 0xFF) >> (11 - bit_position_in_byte))
                                 :
            data[index] >>> (3 - bit_position_in_byte));
                   buffer.append (MODIFIED_BASE32[value & 0x1F]);
                  }
                return buffer.toString ();
              }
            catch (IOException e)
              {
                throw new RuntimeException (e);
              }
          }
        return "N/A";
      }

    public static String getDeviceID (X509Certificate device_certificate_or_null, char optional_divider)
      {
        try
          {
            return getDeviceID (device_certificate_or_null == null ? null : device_certificate_or_null.getEncoded (), optional_divider);
          }
        catch (GeneralSecurityException e)
          {
            throw new RuntimeException (e);
          }
      }
  }
