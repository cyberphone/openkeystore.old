package org.webpki.xmldsig;

import java.io.IOException;


public enum CanonicalizationAlgorithms
  {
    C14N_INCL               ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
    C14N_INCL_WITH_COMMENTS ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"),
    C14N_EXCL               ("http://www.w3.org/2001/10/xml-exc-c14n#"),
    C14N_EXCL_WITH_COMMENTS ("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

    private final String uri;       // As expressed in XML messages

    private CanonicalizationAlgorithms (String uri)
      {
        this.uri = uri;
      }


    public String getURI ()
      {
        return uri;
      }


    public static boolean testAlgorithmURI (String uri)
      {
        for (CanonicalizationAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return true;
              }
          }
        return false;
      }


    public static CanonicalizationAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (CanonicalizationAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }

  }
