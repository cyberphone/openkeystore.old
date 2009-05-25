package org.webpki.keygen2;

import java.io.IOException;


public enum PINGrouping
  {
    NONE                     ("none"),
    SHARED                   ("shared"),
    SIGNATURE_PLUS_STANDARD  ("signature+standard"),
    UNIQUE                   ("unique");

    private final String xml_name;       // As expressed in XML

    private PINGrouping (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static PINGrouping getPINGroupingFromString (String xml_name) throws IOException
      {
        for (PINGrouping option : PINGrouping.values ())
          {
            if (xml_name.equals (option.xml_name))
              {
                return option;
              }
          }
        throw new IOException ("Unknown group: " + xml_name);
      }

  }
