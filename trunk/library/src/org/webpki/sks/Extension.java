package org.webpki.sks;

import java.io.UnsupportedEncodingException;
import java.util.LinkedHashMap;

public class Extension
  {
    byte[] qualifier;
    byte[] extension_data;
    byte base_type;

    public Extension (byte[] qualifier, byte[] extension_data, byte base_type)
      {
        this.qualifier = qualifier;
        this.extension_data = extension_data;
        this.base_type = base_type;
      }
    
    public byte[] getQualifier ()
      {
        return qualifier;
      }
    
    public byte getBaseType ()
      {
        return base_type;
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
        if (base_type != 0x02) throw new SKSException ("Not a \"PropertyBag\"");
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
