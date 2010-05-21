/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.keygen2;

import java.io.IOException;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

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
    
    ServerSessionKeyInterface sess_key_interface;
    
    // Constructors

    public CredentialDeploymentRequestEncoder (String submit_url, 
                                               ServerCredentialStore server_credential_store,
                                               ServerSessionKeyInterface sess_key_interface) throws IOException
      {
        this.submit_url = submit_url;
        this.server_credential_store = server_credential_store;
        this.sess_key_interface = sess_key_interface;
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
        return server_credential_store.mac (data, method, sess_key_interface);
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
                ServerCredentialStore.MacGenerator set_certificate = new ServerCredentialStore.MacGenerator ();
                set_certificate.addArray (key.public_key.getEncoded ());
                set_certificate.addString (key.id);
                X509Certificate[] certificate_path = CertificateUtil.getSortedPath (key.certificate_path);
                for (X509Certificate certificate : certificate_path)
                  {
                    set_certificate.addArray (certificate.getEncoded ());
                  }
                mac (wr, set_certificate.getResult (), APIDescriptors.SET_CERTIFICATE_PATH);
                XMLSignatureWrapper.writeX509DataSubset (wr, certificate_path);
                byte[] ee_cert = certificate_path[0].getEncoded ();
                
                ////////////////////////////////////////////////////////////////////////
                // Optional: "piggybacked" symmetric key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_symmetric_key != null)
                  {
                    wr.addBinary (SYMMETRIC_KEY_ELEM, key.encrypted_symmetric_key);
                    ServerCredentialStore.MacGenerator set_symkey = new ServerCredentialStore.MacGenerator ();
                    set_symkey.addArray (ee_cert);
                    set_symkey.addArray (key.getEncryptedSymmetricKey ());
                    for (String algorithm : getSortedAlgorithms (key.endorsed_algorithms))
                      {
                        set_symkey.addString (algorithm);
                      }
                    mac (wr, set_symkey.getResult (), APIDescriptors.SET_SYMMETRIC_KEY);
                    wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, key.endorsed_algorithms);
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: property bags, extensions, and logotypes
                ////////////////////////////////////////////////////////////////////////
                for (ServerCredentialStore.ExtensionInterface ei : key.extensions.values ())
                  {
                    ServerCredentialStore.MacGenerator add_ext = new ServerCredentialStore.MacGenerator ();
                    add_ext.addArray (ee_cert);
                    add_ext.addByte (ei.getBaseType ());
                    add_ext.addArray (ei.getQualifier ());
                    add_ext.addString (ei.type);
                    add_ext.addBlob (ei.getExtensionData ());
                    ei.writeExtension (wr, mac (add_ext.getResult (), APIDescriptors.ADD_EXTENSION_DATA));
                  }
                wr.getParent ();
              }

            ////////////////////////////////////////////////////////////////////////
            // Done with the crypto, now set the "closeProvisioningSession" MAC
            ////////////////////////////////////////////////////////////////////////
            ServerCredentialStore.MacGenerator close = new ServerCredentialStore.MacGenerator ();
            close.addString (server_credential_store.client_session_id);
            close.addString (server_credential_store.server_session_id);
            close.addString (server_credential_store.issuer_uri);
            top.setAttribute (CLOSE_SESSION_MAC_ATTR,
                              new Base64 ().getBase64StringFromBinary (mac (close.getResult (),
                                                                            APIDescriptors.CLOSE_PROVISIONING_SESSION)));
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
