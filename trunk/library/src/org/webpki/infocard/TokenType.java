package org.webpki.infocard;

import java.io.IOException;


public enum TokenType
  {
    SAML_1_0   ("urn:oasis:names:tc:SAML:1.0:assertion"),
    SAML_1_1   ("urn:oasis:names:tc:SAML:1.1:assertion"),
    SAML_2_0   ("urn:oasis:names:tc:SAML:2.0:assertion");

    private final String xml_name;       // As expressed in XML

    private TokenType (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static TokenType getTokenTypeFromString (String xml_name) throws IOException
      {
        for (TokenType tt : TokenType.values ())
          {
            if (xml_name.equals (tt.xml_name))
              {
                return tt;
              }
          }
        throw new IOException ("Unknown token type: " + xml_name);
      }

  }
