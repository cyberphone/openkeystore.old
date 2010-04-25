// This is the base class which is extended by "KeyOperationResponse" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.xml.ServerCookie;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class KeyInitializationResponse extends XMLObjectWrapper
  {
    String client_session_id;

    String server_session_id;

    ServerCookie server_cookie;                         // Optional

    KeyInitializationResponse () {}

    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
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
        return "KeyInitializationResponse";
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
