// This is the base class which is extended by "KeyOperationRequest" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;

import java.security.interfaces.ECPublicKey;
import java.util.Date;

import org.webpki.xml.ServerCookie;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class ProvisioningSessionRequest extends XMLObjectWrapper
  {
    ProvisioningSessionRequest () {}

    String server_session_id;

    Date server_time;

    String submit_url;
    
    ECPublicKey server_ephemeral_key;

    int session_life_time;

    int session_key_limit;

    ServerCookie server_cookie;

    boolean session_updatable_flag = false;

    String session_key_algorithm = KeyGen2URIs.ALGORITHMS.SESSION_KEY_1;


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
        return "ProvisioningSessionRequest";
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
