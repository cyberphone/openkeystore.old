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

import java.io.UnsupportedEncodingException;

import java.util.LinkedHashMap;

public class Extension
  {
    String qualifier;
    byte[] extension_data;
    byte sub_type;

    public Extension (byte sub_type, String qualifier, byte[] extension_data)
      {
        this.sub_type = sub_type;
        this.qualifier = qualifier;
        this.extension_data = extension_data;
      }
    
    public String getQualifier ()
      {
        return qualifier;
      }
    
    public byte getSubType ()
      {
        return sub_type;
      }
    
    public byte[] getExtensionData ()
      {
        return extension_data;
      }
    
    
    private int getShort (int index)
      {
        return ((extension_data[index++] << 8) & 0xFF00) + (extension_data[index] & 0xFF);
      }
    
    public Property[] getProperties () throws SKSException
      {
        LinkedHashMap<String,Property> properties = new LinkedHashMap<String,Property> ();
        if (sub_type != SecureKeyStore.SUB_TYPE_PROPERTY_BAG) throw new SKSException ("Not a \"PropertyBag\"");
        int i = 0;
        try
          {
            while (i != extension_data.length)
              {
                int nam_len = getShort (i);
                i += 2;
                String name = new String (extension_data, i, nam_len, "UTF-8");
                i += nam_len;
                boolean writable = extension_data[i] == 0x01;
                int val_len = getShort (++i);
                i += 2;
                String value = new String (extension_data, i, val_len, "UTF-8");
                i += val_len;
                if (properties.put (name, new Property (name, writable, value)) != null)
                  {
                    throw new SKSException ("Duplicate property: " + name);
                  }
              }
            return properties.values ().toArray (new Property[0]);
          }
        catch (UnsupportedEncodingException e)
          {
            throw new SKSException (e, SKSException.ERROR_INTERNAL);
          }
      }
  }
