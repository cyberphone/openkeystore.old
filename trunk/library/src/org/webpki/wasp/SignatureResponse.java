// This is the base class which is extended by WASP "SignatureResponse" Encoder and Decoder
package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.wasp.WASPConstants.*;


abstract class SignatureResponse extends XMLObjectWrapper
  {

    SignatureResponse () {}

    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (WASP_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return WASP_NS;
      }

    
    public String element ()
      {
        return "SignatureResponse";
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
