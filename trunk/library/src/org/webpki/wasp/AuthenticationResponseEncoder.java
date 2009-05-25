package org.webpki.wasp;

import java.io.IOException;

import java.util.Date;

import org.w3c.dom.Element;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationResponseEncoder extends AuthenticationResponse
  {

    private String request_url;

    private String submit_url;

    private String id;

    private Date client_time;

    private String server_time;

    private byte[] server_certificate_sha1;

    private ServerCookie server_cookie;

    private IdentityProviderAssertions idp_assertions;

    private boolean add_new_line = true;

    private String prefix;  // Default: no prefix


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public IdentityProviderAssertions setIdentityProviderAssertions (IdentityProviderAssertions idp_assertions)
      {
        return this.idp_assertions = idp_assertions;
      }


    public void createSignedResponse (SignerInterface signer,
                                      AuthenticationRequestDecoder auth_req_decoder,
                                      String request_url,
                                      Date client_time,
                                      byte[] server_certificate_sha1) throws IOException
      {
        this.id = auth_req_decoder.getID ();
        this.server_time = auth_req_decoder.getServerTime ();
        this.request_url = request_url;
        this.submit_url = auth_req_decoder.getSubmitURL ();
        this.client_time = client_time;
        this.server_certificate_sha1 = server_certificate_sha1;
        this.server_cookie = auth_req_decoder.getServerCookie ();
        Element elem = forcedDOMRewrite ();
        if (add_new_line)
          {
            elem.appendChild (getRootDocument ().createTextNode ("\n"));
          }
        
        AuthenticationRequestDecoder.AuthenticationProfile selected_auth_profile = auth_req_decoder.getAuthenticationProfiles ()[0];
        XMLSigner ds = new XMLSigner (signer);
        ds.setSignatureAlgorithm (selected_auth_profile.getSignatureAlgorithm ());
        ds.setDigestAlgorithm (selected_auth_profile.getDigestAlgorithm ());
        ds.setTransformAlgorithm (selected_auth_profile.getCanonicalizationAlgorithm ());
        ds.setCanonicalizationAlgorithm  (selected_auth_profile.getCanonicalizationAlgorithm ());
        ds.setExtendedCertPath (selected_auth_profile.getExtendedCertPath ());
        ds.setSignedKeyInfo (selected_auth_profile.getSignedKeyInfo ());

        ds.createEnvelopedSignature (getRootDocument (), id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        wr.setStringAttribute (ID_ATTR, id);

        wr.setStringAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        wr.setStringAttribute (REQUEST_URL_ATTR, request_url);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);

        if (server_certificate_sha1 != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_SHA1_ATTR, server_certificate_sha1);
          }

        if (server_cookie != null)
          {
            add_new_line = false;
            server_cookie.write (wr);
          }

        if (idp_assertions != null)
          {
            add_new_line = false;
            idp_assertions.write (wr);
          }
      }

  }
