// This is the base class which is extended by "KeyOperationRequest" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.HashAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class KeyInitializationRequest extends XMLObjectWrapper implements Serializable
  {
    private static final long serialVersionUID = 1L;

    KeyInitializationRequest () {}

    String server_session_id;

    String client_session_id;

    private byte[] session_nonce;

    byte[] getSessionHash () throws IOException
      {
        if (session_nonce == null)
          {
            session_nonce = HashAlgorithms.SHA256.digest (
                               new StringBuffer (client_session_id).append ('\0').
                                         append (server_session_id).append ('\0').toString ().getBytes ("UTF-8")
                                                       );
          }
        return session_nonce;
      }

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
        return "KeyInitializationRequest";
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
