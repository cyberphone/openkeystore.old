/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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

import java.io.ByteArrayOutputStream;

import java.security.cert.X509Certificate;

import org.webpki.crypto.HashAlgorithms;

public class DeviceID
  {
    private DeviceID () {}  // No instantiation
    
    private static final char[] MODIFIED_BASE32 = {'A','B','C','D','E','F','G','H',
                                                   'I','J','K','L','M','N','7','P',
                                                   'Q','R','S','T','U','V','W','X',
                                                   'Y','Z','1','2','3','4','5','6'};

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

    public static String getDeviceID (X509Certificate device_certificate_or_null)
      {
        if (device_certificate_or_null != null)
          {
            try
              {
                byte[] sha1 = HashAlgorithms.SHA1.digest (device_certificate_or_null.getEncoded ());
                ByteArrayOutputStream baos = new ByteArrayOutputStream ();
                baos.write (sha1);
                baos.write (half (half (half (sha1))));
                byte[] data = baos.toByteArray ();
                StringBuffer buffer = new StringBuffer ();
                for (int bit_position = 0; bit_position < 180; bit_position += 5)
                  {
                    if (bit_position > 0 && bit_position % 20 == 0)
                      {
                        buffer.append ('-');
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
            catch (Exception e)
              {
                throw new RuntimeException (e);
              }
          }
        return "N/A";
      }
  }
