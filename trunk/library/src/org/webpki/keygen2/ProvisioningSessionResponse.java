// This is the base class which is extended by "KeyOperationResponse" Encoder and Decoder
package org.webpki.keygen2;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import java.util.Date;

import org.webpki.xml.ServerCookie;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class ProvisioningSessionResponse extends XMLObjectWrapper
  {
    ProvisioningSessionResponse () {}

    String server_session_id;
    
    String client_session_id;

    Date server_time;
    
    Date client_time;
    
    ECPublicKey client_ephemeral_key;

    byte[] session_attestation;
    
    ServerCookie server_cookie;
    
    X509Certificate[] device_certificate_path;

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
        return "ProvisioningSessionResponse";
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
