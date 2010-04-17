package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;
import java.util.Vector;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationResponseEncoder extends KeyInitializationResponse
  {
    private Date client_time;

    private Date server_time;

    private Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey> ();

    private String prefix;  // Default: no prefix

    private String key_attestation_algorithm = KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1;

    private boolean need_ds11_namespace;


    private class GeneratedPublicKey
      {
        String id;

        PublicKey public_key;

        byte[] key_attestation;

        byte[] encrypted_private_key;                 // defined for archivalable keys only

        GeneratedPublicKey (String id)
          {
            this.id = id;
            generated_keys.add (this);
          }

        public String getID ()
          {
            return id; 
          }

      }


    public void addPublicKey (PublicKey public_key, byte[] key_attestation, String id, byte[] encrypted_private_key) throws IOException
      {
        GeneratedPublicKey gk = new GeneratedPublicKey (id);
        gk.public_key = public_key;
        if (public_key instanceof ECPublicKey)
          {
            need_ds11_namespace = true;
          }
        gk.key_attestation = key_attestation;
        gk.encrypted_private_key = encrypted_private_key;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    @SuppressWarnings("unused")
    private KeyInitializationResponseEncoder () {}


    public KeyInitializationResponseEncoder (String client_session_id, String server_session_id, Date server_time, Date client_time) throws IOException
      {
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
        this.server_time = server_time;
        this.client_time = client_time;
      }


    public void setKeyAttestationAlgorithm (String key_attestation_algorithm_uri)
      {
        this.key_attestation_algorithm = key_attestation_algorithm_uri;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (need_ds11_namespace)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);
        
        wr.setStringAttribute (KEY_ATTESTATION_ALGORITHM_ATTR, key_attestation_algorithm);

        for (GeneratedPublicKey gk : generated_keys)
          {
            wr.addChildElement (GENERATED_PUBLIC_KEY_ELEM);
            wr.setStringAttribute (ID_ATTR, gk.id);
            wr.setBinaryAttribute (KEY_ATTESTATION_ATTR, gk.key_attestation);
            XMLSignatureWrapper.writePublicKey (wr, gk.public_key);
            if (gk.encrypted_private_key != null)
              {
                wr.addBinary(PRIVATE_KEY_ELEM, gk.encrypted_private_key);
              }
            wr.getParent ();
          }

        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
