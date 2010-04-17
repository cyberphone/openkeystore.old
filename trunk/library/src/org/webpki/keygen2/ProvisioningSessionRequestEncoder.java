package org.webpki.keygen2;

import java.io.IOException;

import java.security.interfaces.ECPublicKey;

import java.util.Date;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionRequestEncoder extends ProvisioningSessionRequest
  {
    String prefix;  // Default: no prefix
    
    private boolean did_set_session_updatable;


    // Constructors

    public ProvisioningSessionRequestEncoder (ECPublicKey server_ephemeral_key,
                                              String server_session_id,
                                              String submit_url,
                                              int session_life_time,
                                              int session_key_limit)  throws IOException
      {
        super.server_ephemeral_key = server_ephemeral_key;
        super.server_session_id = server_session_id;
        super.submit_url = submit_url;
        super.session_life_time = session_life_time;
        super.session_key_limit = session_key_limit;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }


    public void setUpdatable (boolean session_updatable_flag)
      {
        did_set_session_updatable = true;
        super.session_updatable_flag = session_updatable_flag;
      }


    public void setSessionKeyAlgorithm (String session_key_algorithm)
      {
        super.session_key_algorithm = session_key_algorithm;
      }

    public void setServerTime (Date server_time)
      {
        super.server_time = server_time;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

         if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        if (did_set_session_updatable)
          {
            wr.setBooleanAttribute (UPDATABLE_ATTR, session_updatable_flag);
          }
        
        wr.setIntAttribute (SESSION_LIFE_TIME_ATTR, session_life_time);

        wr.setIntAttribute (SESSION_KEY_LIMIT_ATTR, session_key_limit);

        wr.setStringAttribute (SESSION_KEY_ALGORITHM_ATTR, session_key_algorithm);

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (SERVER_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, server_ephemeral_key);
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
