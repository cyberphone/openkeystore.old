package org.webpki.keygen2;

import java.io.IOException;


public enum PassphraseFormats
  {
    NUMERIC       ("numeric"),
    ALPHANUMERIC  ("alphanumeric"),
    PRINTABLE     ("printable"),
    HEX2BYTES     ("hex2bytes");

    private final String xml_name;       // As expressed in XML

    private PassphraseFormats (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static PassphraseFormats getPassphraseFormatFromString (String xml_name) throws IOException
      {
        for (PassphraseFormats type : PassphraseFormats.values ())
          {
            if (xml_name.equals (type.xml_name))
              {
                return type;
              }
          }
        throw new IOException ("Unknown format: " + xml_name);
      }

  }
