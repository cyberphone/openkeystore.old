package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.w3c.dom.Document;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeySigner;

import org.webpki.crypto.SymKeySignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionResponseEncoder extends ProvisioningSessionResponse
  {

    String prefix;  // Default: no prefix
    
     // Constructors

    @SuppressWarnings("unused")
    private ProvisioningSessionResponseEncoder () {}


    public ProvisioningSessionResponseEncoder (ECPublicKey client_ephemeral_key,
                                               String server_session_id,
                                               String client_session_id,
                                               Date server_time,
                                               Date client_time,
                                               byte[] session_attestation,
                                               X509Certificate[] device_certificate_path)  throws IOException
      {
        super.client_ephemeral_key = client_ephemeral_key;
        super.server_session_id = server_session_id;
        super.client_session_id = client_session_id;
        super.server_time = server_time;
        super.client_time = client_time;
        super.session_attestation = session_attestation;
        super.device_certificate_path = device_certificate_path;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }



    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SymKeySignerInterface signer) throws IOException
      {
        XMLSymKeySigner ds = new XMLSymKeySigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);
        XMLSignatureWrapper.addXMLSignatureNS (wr);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);
        
        wr.setBinaryAttribute (SESSION_ATTESTATION_ATTR, session_attestation);

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (CLIENT_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, client_ephemeral_key);
        wr.getParent();

        ////////////////////////////////////////////////////////////////////////
        // Device certificate path
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (DEVICE_CERTIFICATE_ELEM);
        XMLSignatureWrapper.writeX509DataSubset (wr, device_certificate_path);
        wr.getParent();

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
