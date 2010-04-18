package org.webpki.keygen2;

import java.io.IOException;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

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

    ServerCredentialStore ics;
    
    MACInterface mac_interface;
    
    // Constructors

    public CredentialDeploymentRequestEncoder (String submit_url, 
                                               ServerCredentialStore ics,
                                               MACInterface mac_interface) throws IOException
      {
        this.submit_url = submit_url;
        this.ics = ics;
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
        ds.createEnvelopedSignature (doc, ics.server_session_id);
      }
    
    
    private byte[] mac (byte[] data) throws IOException, GeneralSecurityException
      {
        return mac_interface.getMac (data, ics.mac_sequence_counter++);
      }
    
    
    private void mac (DOMWriterHelper wr, byte[] data) throws IOException, GeneralSecurityException
      {
        wr.setBinaryAttribute (MAC_ATTR, mac (data));
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        Element top = wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, ics.client_session_id);

        wr.setStringAttribute (ID_ATTR, ics.server_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (ics.getKeyProperties ().isEmpty ())
          {
            throw new IOException ("Empty request not allowed!");
          }

        ////////////////////////////////////////////////////////////////////////
        // Write [1..n] Credentials
        ////////////////////////////////////////////////////////////////////////
        try
          {
            for (ServerCredentialStore.KeyProperties certified_key : ics.getKeyProperties ())
              {
                wr.addChildElement (CERTIFIED_PUBLIC_KEY_ELEM);
                wr.setStringAttribute (ID_ATTR, certified_key.id);

                ////////////////////////////////////////////////////////////////////////
                // Always: the X509 Certificate
                ////////////////////////////////////////////////////////////////////////
                X509Certificate[] certificate_path = CertificateUtil.getSortedPath (certified_key.certificate_path);
                byte[] ee_cert = certificate_path[0].getEncoded ();
                mac (wr, ArrayUtil.add (certified_key.public_key.getEncoded (),
                                        ArrayUtil.add (certified_key.id.getBytes ("UTF-8"), ee_cert)));
                XMLSignatureWrapper.writeX509DataSubset (wr, certificate_path);

                ////////////////////////////////////////////////////////////////////////
                // Optional: "piggybacked" symmetric key
                ////////////////////////////////////////////////////////////////////////
                if (certified_key.encrypted_symmetric_key != null)
                  {
                    wr.addBinary (SYMMETRIC_KEY_ELEM, certified_key.encrypted_symmetric_key);
                    byte[] endorsed_algorithms = new byte[0];
                    for (String algorithm : getSortedAlgorithms (certified_key.endorsed_algorithms))
                      {
                        endorsed_algorithms = ArrayUtil.add (endorsed_algorithms, algorithm.getBytes ("UTF-8"));
                      }
                    mac (wr, ArrayUtil.add (ee_cert, ArrayUtil.add (certified_key.encrypted_symmetric_key, endorsed_algorithms)));
                    wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, certified_key.endorsed_algorithms);
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: property bags, extensions, and logotypes
                ////////////////////////////////////////////////////////////////////////
                for (ServerCredentialStore.ExtensionInterface ei : certified_key.extensions.values ())
                  {
                    ei.writeExtension (wr,
                                       mac (ArrayUtil.add (ee_cert, 
                                                 ArrayUtil.add (
                                                      ArrayUtil.add (new byte[]{ei.getBaseType ()}, ei.getQualifier ()),
                                                           ArrayUtil.add (ei.type.getBytes ("UTF-8"), ei.getExtensionData ())))));
                  }
                wr.getParent ();
             }
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

        ////////////////////////////////////////////////////////////////////////
        // Finally, set the "closeProvisioningSession" MAC
        ////////////////////////////////////////////////////////////////////////
        top.setAttribute (SESSION_MAC_ATTR, new Base64 ().getBase64StringFromBinary (new byte[]{5,6}));
      }

  }
