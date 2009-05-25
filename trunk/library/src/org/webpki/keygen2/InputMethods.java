package org.webpki.keygen2;

import java.io.IOException;


public enum InputMethods
  {
    ANY           ("any"),
    PROGRAMMATIC  ("programmatic"),
    TRUSTED_GUI   ("trusted-gui");

    private final String xml_name;       // As expressed in XML

    private InputMethods (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static InputMethods getMethodFromString (String xml_name) throws IOException
      {
        for (InputMethods type : InputMethods.values ())
          {
            if (xml_name.equals (type.xml_name))
              {
                return type;
              }
          }
        throw new IOException ("Unknown method: " + xml_name);
      }

  }
