package org.webpki.keygen2;

import java.io.IOException;


import org.w3c.dom.Document;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
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

    boolean xml_enc;

    IssuerCredentialStore ics;
    
    MACInterface mac_interface;
    
    byte[] session_hash;


    // Constructors

    @SuppressWarnings("unused")
    private CredentialDeploymentRequestEncoder () {}


    public CredentialDeploymentRequestEncoder (String submit_url, 
                                               IssuerCredentialStore ics,
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
    
    
    private void mac (DOMWriterHelper wr, byte[] data) throws IOException, GeneralSecurityException
      {
        wr.setBinaryAttribute (MAC_ATTR, mac_interface.getMac (data));
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

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
            for (IssuerCredentialStore.KeyProperties certified_key : ics.getKeyProperties ())
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
                for (IssuerCredentialStore.ExtensionInterface ei : certified_key.extensions.values ())
                  {
                    byte[] mac_data = 
                           mac_interface.getMac (
                                ArrayUtil.add (ee_cert, 
                                     ArrayUtil.add (
                                          ArrayUtil.add (new byte[]{ei.getBaseType ()}, ei.getQualifier ()),
                                               ArrayUtil.add (ei.type.getBytes ("UTF-8"), ei.getExtensionData ()))));
                    ei.writeExtension (wr, mac_data);
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

      }

  }
