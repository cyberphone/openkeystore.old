package org.webpki.keygen2;

import java.io.IOException;

import java.util.Vector;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyInitializationRequestEncoder extends KeyInitializationRequest
  {
    String submit_url;

    boolean deferred_certification;

    String prefix;  // Default: no prefix

    ServerCookie server_cookie;
    
    ServerCredentialStore ics;
    
    private boolean need_signature_ns;
    
    Vector<String> written_pin = new Vector<String> ();

    Vector<String> written_puk = new Vector<String> ();

    private String key_attestation_algorithm = KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1;


    // Constructors

    public KeyInitializationRequestEncoder (String submit_url,
                                            ServerCredentialStore ics) throws IOException
      {
        this.submit_url = submit_url;
        this.ics = ics;
      }


    private static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    public void setDeferredCertification (boolean flag)
      {
        deferred_certification = flag;
      }


    public void setKeyAttestationAlgorithm (String key_attestation_algorithm_uri)
      {
        this.key_attestation_algorithm = key_attestation_algorithm_uri;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        need_signature_ns = true;
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, ics.server_session_id);
      }
    
    
    private ServerCredentialStore.PUKPolicy getPUKPolicy (ServerCredentialStore.KeyProperties kp)
      {
        return kp.pin_policy == null ? null : kp.pin_policy.puk_policy;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        if (need_signature_ns)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, ics.server_session_id);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, ics.client_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        wr.setStringAttribute (KEY_ATTESTATION_ALGORITHM_ATTR, key_attestation_algorithm);

        if (deferred_certification)
          {
            wr.setBooleanAttribute (DEFERRED_CERTIFICATION_ATTR, deferred_certification);
          }

        ////////////////////////////////////////////////////////////////////////
        // There MUST not be zero keys to initialize...
        ////////////////////////////////////////////////////////////////////////
        if (ics.requested_keys.isEmpty ())
          {
            bad ("Empty request not allowd!");
          }
        ServerCredentialStore.KeyProperties last_req_key = null;
        for (ServerCredentialStore.KeyProperties req_key : ics.requested_keys.values ())
          {
            if (last_req_key != null && getPUKPolicy (last_req_key) != null &&
                getPUKPolicy (last_req_key) != getPUKPolicy (req_key))
              {
                wr.getParent ();
              }
            if (last_req_key != null && last_req_key.pin_policy != null &&
                last_req_key.pin_policy != req_key.pin_policy)
              {
                wr.getParent ();
              }
            if (getPUKPolicy (req_key) != null)
              {
                if (written_puk.contains (getPUKPolicy (req_key).id))
                  {
                    if (getPUKPolicy (last_req_key) != getPUKPolicy (req_key))
                      {
                        bad ("PUK grouping error");
                      }
                  }
                else
                  {
                    getPUKPolicy (req_key).writePolicy (wr);
                    written_puk.add (getPUKPolicy (req_key).id);
                  }
              }
            if (req_key.pin_policy != null)
              {
                if (written_pin.contains (req_key.pin_policy.id))
                  {
                    if (last_req_key.pin_policy != req_key.pin_policy)
                      {
                        bad ("PIN grouping error");
                      }
                  }
                else
                  {
                    req_key.pin_policy.writePolicy (wr);
                    written_pin.add (req_key.pin_policy.id);
                  }
              }
            req_key.writeRequest (wr);
            last_req_key = req_key;
          }
        if (last_req_key != null && last_req_key.pin_policy != null)
          {
            wr.getParent ();
          }
        if (last_req_key != null && getPUKPolicy (last_req_key) != null)
          {
            wr.getParent ();
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
