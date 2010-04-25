package org.webpki.keygen2;

import java.io.IOException;


public enum KeyUsage
  {
    SIGNATURE                  ("signature"),
    AUTHENTICATION             ("authentication"),
    ENCRYPTION                 ("encryption"),
    UNIVERSAL                  ("universal"),
    TRANSPORT                  ("transport"),
    SYMMETRIC_KEY              ("symmetric-key");

    private final String xml_name;       // As expressed in XML

    private KeyUsage (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static KeyUsage getKeyUsageFromString (String xml_name) throws IOException
      {
        for (KeyUsage key_type : KeyUsage.values ())
          {
            if (xml_name.equals (key_type.xml_name))
              {
                return key_type;
              }
          }
        throw new IOException ("Unknown key-type: " + xml_name);
      }

  }
