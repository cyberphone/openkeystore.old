// This is the base class which is extended by "PlatformNegotiationResponse" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class PlatformNegotiationResponse extends XMLObjectWrapper implements Serializable
  {

    private static final long serialVersionUID = 1L;

    PlatformNegotiationResponse () {}

    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (REDUCED_XML_ENC_SCHEMA_FILE);
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    public String element ()
      {
        return "PlatformNegotiationResponse";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
