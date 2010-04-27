package org.webpki.keygen2;

import java.io.IOException;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.webpki.sks.SessionKeyOperations;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class CredentialDeploymentRequestEncoder extends CredentialDeploymentRequest
  {
    String submit_url;

    private String prefix;  // Default: no prefix

    ServerCookie server_cookie;

    ServerCredentialStore server_credential_store;
    
    SessionKeyOperations mac_interface;
    
    // Constructors

    public CredentialDeploymentRequestEncoder (String submit_url, 
                                               ServerCredentialStore server_credential_store,
                                               SessionKeyOperations mac_interface) throws IOException
      {
        this.submit_url = submit_url;
        this.server_credential_store = server_credential_store;
        this.mac_interface = mac_interface;
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
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_credential_store.server_session_id);
      }
    
    
    private byte[] mac (byte[] data, APIDescriptors method) throws IOException, GeneralSecurityException
      {
        return mac_interface.getMac (data, ArrayUtil.add (method.getBinary (), server_credential_store.getMACSequenceCounterAndUpdate ()));
      }
    
    
    private void mac (DOMWriterHelper wr, byte[] data, APIDescriptors method) throws IOException, GeneralSecurityException
      {
        wr.setBinaryAttribute (MAC_ATTR, mac (data, method));
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        Element top = wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, server_credential_store.client_session_id);

        wr.setStringAttribute (ID_ATTR, server_credential_store.server_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (server_credential_store.getKeyProperties ().isEmpty ())
          {
            throw new IOException ("Empty request not allowed!");
          }

        ////////////////////////////////////////////////////////////////////////
        // Write [1..n] Credentials
        ////////////////////////////////////////////////////////////////////////
        try
          {
            for (ServerCredentialStore.KeyProperties key : server_credential_store.getKeyProperties ())
              {
                wr.addChildElement (CERTIFIED_PUBLIC_KEY_ELEM);
                wr.setStringAttribute (ID_ATTR, key.id);

                ////////////////////////////////////////////////////////////////////////
                // Always: the X509 Certificate(s)
                ////////////////////////////////////////////////////////////////////////
                byte[] data =  ArrayUtil.add (key.public_key.getEncoded (), key.id.getBytes ("UTF-8"));
                X509Certificate[] certificate_path = CertificateUtil.getSortedPath (key.certificate_path);
                for (X509Certificate certificate : certificate_path)
                  {
                    data = ArrayUtil.add (data, certificate.getEncoded ());
                  }
                mac (wr, data, APIDescriptors.SET_CERTIFICATE_PATH);
                XMLSignatureWrapper.writeX509DataSubset (wr, certificate_path);
                byte[] ee_cert = certificate_path[0].getEncoded ();
                
                ////////////////////////////////////////////////////////////////////////
                // Optional: "piggybacked" symmetric key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_symmetric_key != null)
                  {
                    wr.addBinary (SYMMETRIC_KEY_ELEM, key.encrypted_symmetric_key);
                    byte[] endorsed_algorithms = new byte[0];
                    for (String algorithm : getSortedAlgorithms (key.endorsed_algorithms))
                      {
                        endorsed_algorithms = ArrayUtil.add (endorsed_algorithms, algorithm.getBytes ("UTF-8"));
                      }
                    mac (wr,
                         ArrayUtil.add (ee_cert, ArrayUtil.add (key.encrypted_symmetric_key, endorsed_algorithms)),
                         APIDescriptors.SET_SYMMETRIC_KEY);
                    wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, key.endorsed_algorithms);
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: property bags, extensions, and logotypes
                ////////////////////////////////////////////////////////////////////////
                for (ServerCredentialStore.ExtensionInterface ei : key.extensions.values ())
                  {
                    ei.writeExtension (wr,
                                       mac (ArrayUtil.add (ee_cert, 
                                                 ArrayUtil.add (
                                                      ArrayUtil.add (new byte[]{ei.getBaseType ()}, ei.getQualifier ()),
                                                           ArrayUtil.add (ei.type.getBytes ("UTF-8"), ei.getExtensionData ()))),
                                            APIDescriptors.ADD_EXTENSION)
                                       );
                  }
                wr.getParent ();
              }

            ////////////////////////////////////////////////////////////////////////
            // Done with the crypto, now set the "closeProvisioningSession" MAC
            ////////////////////////////////////////////////////////////////////////
            top.setAttribute (CLOSE_SESSION_MAC_ATTR,
                              new Base64 ().getBase64StringFromBinary (
                                  mac (new StringBuffer ().append (server_credential_store.client_session_id)
                                      .append (server_credential_store.server_session_id)
                                      .append (server_credential_store.issuer_uri).toString ().getBytes ("UTF-8"),
                                              APIDescriptors.CLOSE_SESSION)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
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
