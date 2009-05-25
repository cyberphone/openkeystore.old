package org.webpki.wasp;

import java.io.IOException;

import java.util.GregorianCalendar;

import java.security.cert.X509Certificate;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.util.ArrayUtil;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.SignedKeyInfoSpecifier;

import org.webpki.crypto.CertificateFilter;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationResponseDecoder extends AuthenticationResponse
  {

    // Attributes
    private String id;

    private GregorianCalendar server_time;

    private String submit_url;

    private String request_url;

    private GregorianCalendar client_time;

    private byte[] server_certificate_sha1;                     // Optional

    private ServerCookie server_cookie;                         // Optional

    private IdentityProviderAssertions idp_assertions;          // Optional

    private XMLSignatureWrapper signature;

    private X509Certificate[] signer_certpath;



    public IdentityProviderAssertions getIdentityProviderAssertions ()
      {
        return idp_assertions;
      }
 
    
    public String getSubmitURL ()
      {
        return submit_url;
      }
 
    
    public String getRequestURL ()
      {
        return request_url;
      }
 
    
    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }
    
    
    public GregorianCalendar getClientTime ()
    {
        return client_time;
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
        id = ah.getString (ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        request_url = ah.getString (REQUEST_URL_ATTR);

        client_time = ah.getDateTime (CLIENT_TIME_ATTR);

        server_certificate_sha1 = ah.getBinaryConditional (SERVER_CERT_SHA1_ATTR);

        rd.getChild();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        if (rd.hasNext (IDP_ASSERTIONS_ELEM))
          {
            idp_assertions = IdentityProviderAssertions.read (rd);
          }

        signature = (XMLSignatureWrapper) wrap (rd.getNext ());
      }

    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }

    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        XMLVerifier ds = new XMLVerifier (verifier);
        ds.setSignedKeyInfo (SignedKeyInfoSpecifier.ALLOW_SIGNED_KEY_INFO);
        ds.validateEnvelopedSignature (this, null, signature, id);
        signer_certpath = verifier.getSignerCertificatePath ();
      }


    private void bad (String mismatch) throws IOException
      {
        throw new IOException ("Mismatch between request and response: " + mismatch);
      }


    public void checkRequestResponseIntegrity (AuthenticationRequestEncoder areqenc, byte[] expected_sha1) throws IOException
      {
        if (expected_sha1 != null &&
            (server_certificate_sha1 == null || !ArrayUtil.compare (server_certificate_sha1, expected_sha1)))
          {
            bad ("Server certificate SHA1");
          }
        if (!id.equals (areqenc.id))
          {
            bad ("ID attributes");
          }
        if (!DOMWriterHelper.formatDateTime (server_time.getTime ()).equals (DOMWriterHelper.formatDateTime (areqenc.server_time)))
          {
            bad ("ServerTime attribute");
          }
        if (areqenc.cert_filters.size () > 0 && signer_certpath != null)
          {
            for (CertificateFilter cf : areqenc.cert_filters)
              {
                if (cf.matches (signer_certpath, null, null))
                  {
                    return;
                  }
              }
            bad ("Certificates does not match filter(s)");
          }
      }

  }
