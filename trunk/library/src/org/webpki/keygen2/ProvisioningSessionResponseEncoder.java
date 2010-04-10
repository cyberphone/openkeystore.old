package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;

import java.security.interfaces.ECPublicKey;

import org.w3c.dom.Document;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeySigner;

import org.webpki.crypto.SymKeySignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


@SuppressWarnings("serial")
public class ProvisioningSessionResponseEncoder extends ProvisioningSessionResponse
  {
    private static final long serialVersionUID = 1L;

    String prefix;  // Default: no prefix
    
    private boolean did_set_session_updatable;


    // Constructors

    @SuppressWarnings("unused")
    private ProvisioningSessionResponseEncoder () {}


    public ProvisioningSessionResponseEncoder (ECPublicKey client_ephemeral_key,
                                              String server_session_id,
                                              String submit_url,
                                              int session_life_time,
                                              int session_key_limit)  throws IOException
      {
        super.client_ephemeral_key = client_ephemeral_key;
        super.server_session_id = server_session_id;
        super.session_life_time = session_life_time;
        super.session_key_limit = session_key_limit;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }


    public void setServerTime (Date server_time)
      {
        super.server_time = server_time;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SymKeySignerInterface signer) throws IOException
      {
        XMLSymKeySigner ds = new XMLSymKeySigner (signer);
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

        
        wr.setIntAttribute (SESSION_LIFE_TIME_ATTR, session_life_time);

        wr.setIntAttribute (SESSION_KEY_LIMIT_ATTR, session_key_limit);

//        wr.setStringAttribute (SESSION_KEY_ALGORITHM_ATTR, session_key_algorithm);

        ////////////////////////////////////////////////////////////////////////
        // Server Ephemeral Key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (SERVER_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, client_ephemeral_key);
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
