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
    
    private static final char[] REVERSE_BASE32 = new char[256];
    
    static
      {
        for (int i = 0; i < 256; i++)
          {
            REVERSE_BASE32[i] = 256;
          }
        for (char i = 0; i < 32; i++)
          {
            REVERSE_BASE32[MODIFIED_BASE32[i]] = i;
          }
      }

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
    
    public static String getDeviceIDFromSHA1Hash (byte[] sha1)
      {
        try
          {
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            baos.write (sha1);
            baos.write (half (half (half (sha1))));
            byte[] data = baos.toByteArray ();
            StringBuffer buffer = new StringBuffer ();
            for (int bit_position = 0; bit_position < 180; bit_position += 5)
              {
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

    public static String getDeviceID (byte[] identity_blob_or_null)
      {
        if (identity_blob_or_null != null)
          {
            try
              {
                return getDeviceIDFromSHA1Hash (HashAlgorithms.SHA1.digest (identity_blob_or_null));
              }
            catch (IOException e)
              {
                throw new RuntimeException (e);
              }
          }
        return "N/A";
      }

    public static String getDeviceID (X509Certificate device_certificate_or_null)
      {
        try
          {
            return getDeviceID (device_certificate_or_null == null ? null : device_certificate_or_null.getEncoded ());
          }
        catch (GeneralSecurityException e)
          {
            throw new RuntimeException (e);
          }
      }
    
    public static byte[] getSHA1FromDeviceID (String device_id) throws IOException
      {
        if (device_id.length () != 32 && device_id.length () != 36)
          {
            throw new IOException ("DeviceID must be 32 or 36 characters");
          }
        byte[] sha1 = new byte[20];
        int q = 0;
        int bit_position = 0;
        for (int i = 0; i < 32; i++)
          {
            char c = device_id.charAt (i);
            if (c > 255 || (c = REVERSE_BASE32[c]) < 0)
              {
                throw new IOException ("Illigal DeviceID character: " + c);
              }
            if (bit_position < 4)
              {
                if (bit_position == 0)
                  {
                    sha1[q] = 0;
                  }
                sha1[q] |= (byte)(c << (3 - bit_position));
                if (bit_position == 3)
                  {
                    q++;
                  }
              }
            else
              {
                sha1[q] |= (byte)(c >> ((bit_position + 5) % 8));
                sha1[++q] = (byte)(c << (11 - bit_position));
              }
            bit_position = (bit_position + 5) % 8;
          }
        if (device_id.length () == 36)
          {
            if (!device_id.equals (getDeviceIDFromSHA1Hash (sha1)))
              {
                throw new IOException ("DeviceID checksum error");
              }
          }
        return sha1;
      }

    public static void main (String[] args) throws IOException
      {
        if (args.length != 1)
          {
            System.out.println ("\n" + DeviceID.class.getName () + " string-to-be-converted-into-a-device-id\n");
            System.exit (3);
          }
        System.out.println ("Device ID=" + getDeviceID (args[0].getBytes ("UTF-8")));
      }
  }
