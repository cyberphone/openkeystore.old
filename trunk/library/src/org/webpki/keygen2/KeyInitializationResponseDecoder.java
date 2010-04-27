package org.webpki.keygen2;

import java.io.IOException;

import java.util.LinkedHashMap;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.sks.SessionKeyOperations;
import org.webpki.util.ArrayUtil;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationResponseDecoder extends KeyInitializationResponse
  {
    private LinkedHashMap<String,GeneratedPublicKey> generated_keys = new LinkedHashMap<String,GeneratedPublicKey> ();

    class GeneratedPublicKey
      {
        private GeneratedPublicKey () {}

        String id;

        PublicKey public_key;

        byte[] key_attestation;
        
        byte[] encrypted_private_key;

      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }
    
    
    public void validateAndPopulate (KeyInitializationRequestEncoder kire, SessionKeyOperations session_key_operations) throws IOException, GeneralSecurityException
      {
        kire.ics.checkSession (client_session_id, server_session_id);
        if (generated_keys.size () != kire.ics.requested_keys.size ())
          {
            ServerCredentialStore.bad ("Different number of requested and received keys");
          }
        for (GeneratedPublicKey gpk : generated_keys.values ())
          {
            ServerCredentialStore.KeyProperties kp = kire.ics.requested_keys.get (gpk.id);
            if (kp == null)
              {
                ServerCredentialStore.bad ("Missing key id:" + gpk.id);
              }
            kp.public_key = gpk.public_key;
            kp.encrypted_private_key = gpk.encrypted_private_key;
            byte[] data = ArrayUtil.add (gpk.id.getBytes ("UTF-8"), gpk.public_key.getEncoded ());
            if (!ArrayUtil.compare (session_key_operations.getAttest (data), kp.key_attestation = gpk.key_attestation))
              {
                ServerCredentialStore.bad ("Attestation failed for key id:" + gpk.id);
              }
          }
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        do
          {
            GeneratedPublicKey gk = new GeneratedPublicKey ();
            rd.getNext (GENERATED_PUBLIC_KEY_ELEM);
            gk.id = ah.getString (ID_ATTR);
            gk.key_attestation = ah.getBinaryConditional (KEY_ATTESTATION_ATTR);
            rd.getChild ();
            gk.public_key = XMLSignatureWrapper.readPublicKey (rd);
            if (rd.hasNext ())
              {
                gk.encrypted_private_key = rd.getBinary (PRIVATE_KEY_ELEM);
              }
            rd.getParent ();
            if (generated_keys.put (gk.id, gk) != null)
              {
                ServerCredentialStore.bad ("Duplicate key id:" + gk.id);
              }
          }
        while (rd.hasNext (GENERATED_PUBLIC_KEY_ELEM));

        if (rd.hasNext ())  // If not ServerCookie XML validation has gone wrong
          {
            server_cookie = ServerCookie.read (rd);
          }
     }

  }
