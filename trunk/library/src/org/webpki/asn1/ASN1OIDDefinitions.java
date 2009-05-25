package org.webpki.asn1;

import java.io.InputStream;

class ASN1OIDDefinitions
  {
    ASN1OIDDefinitions ()
      {
      }
      
    InputStream getOIDStream ()
      {
        return getClass().getResourceAsStream ("dumpasn1.cfg");
      }
  }
