package org.webpki.wasp.prof.xds;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.Vector;

import java.security.cert.X509Certificate;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.util.ArrayUtil;

import org.webpki.wasp.DocumentSignatures;
import org.webpki.wasp.DocumentReferences;
import org.webpki.wasp.DocumentData;
import org.webpki.wasp.IdentityProviderAssertions;
import org.webpki.wasp.SignatureProfileResponseDecoder;
import org.webpki.wasp.SignatureProfileEncoder;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.SignedKeyInfoSpecifier;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileResponseDecoder extends XMLObjectWrapper implements SignatureProfileResponseDecoder
  {

    // Attributes
    private String id;

    private String submit_url;

    private String request_url;

    private GregorianCalendar client_time;

    private GregorianCalendar server_time;

    private byte[] server_certificate_sha1;                     // Optional

    private String[] unreferenced_attachments;                  // Optional

    // Elements
    private DocumentReferences doc_refs;

    private DocumentSignatures doc_signs;

    private ServerCookie server_cookie;                         // Optional

    private IdentityProviderAssertions idp_assertions;          // Optional

    private XMLSignatureWrapper signature;

    private XMLVerifier ds;

    private X509Certificate[] signer_certpath;


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public void init () throws IOException
      {
        addSchema (XML_SCHEMA_FILE);
      }


    public String namespace ()
      {
        return XML_SCHEMA_NAMESPACE;
      }


    public String element ()
      {
        return RESPONSE_ELEM;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public IdentityProviderAssertions getIdentityProviderAssertions ()
      {
        return idp_assertions;
      }


    public String[] getUnreferencedAttachments ()
      {
        return unreferenced_attachments;
      }

    
    public byte[] getServerCertificateSHA1 ()
      {
        return server_certificate_sha1;
      }

    
    public String getRequestURL ()
      {
        return request_url;
      }

    
    public String getSubmitURL ()
      {
        return submit_url;
      }
 
    
    public GregorianCalendar getServerTime ()
      {
        return server_time;
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

        unreferenced_attachments = ah.getListConditional (UNREFERENCED_ATTACHMENTS_ATTR);

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        doc_refs = DocumentReferences.read (rd);

        doc_signs = DocumentSignatures.read (rd);

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
        ds = new XMLVerifier (verifier);
        ds.setSignedKeyInfo (SignedKeyInfoSpecifier.ALLOW_SIGNED_KEY_INFO);
        ds.validateEnvelopedSignature (this, null, signature, id);
        signer_certpath = verifier.getSignerCertificatePath ();
      }


    private void bad (String what) throws IOException
      {
        throw new IOException (what);
      }


    public boolean match (SignatureProfileEncoder spreenc,
                          DocumentData doc_data,
                          DocumentReferences doc_refs,
                          ServerCookie server_cookie,
                          Vector<CertificateFilter> cert_filters,
                          String id,
                          byte[] expected_sha1)
    throws IOException
      {
        // Is this the same profile?
        if (!(spreenc instanceof XDSProfileRequestEncoder))
          {
            return false;
          }

        // Yes, it was!
        XDSProfileRequestEncoder enc = (XDSProfileRequestEncoder) spreenc;

        // Check that the ID attribute is OK
        if (!this.id.equals (id))
          {
            bad ("Non-matching ID attribute");
          }

        // Check ServerCookie object
        if (this.server_cookie == null)
          {
            if (server_cookie != null) bad ("Unexpected ServerCookie");
          }
        else
          { 
            if (server_cookie == null) bad ("Missing ServerCookie");
            if (!this.server_cookie.equals (server_cookie))
              {
                return false;
              }
          }

        // Check that the document references are OK
        this.doc_refs.check (doc_refs);

        // Check that the document hashes are OK
        if (!(new DocumentSignatures (enc.digest_algorithm, enc.document_canonicalization_algorithm, doc_data).equals (doc_signs)))
          {
            return false;
          }

        if (enc.digest_algorithm != null && enc.digest_algorithm != ds.getDigestAlgorithm ())
          {
            bad ("Wrong digest algorithm.  Requested: " + enc.digest_algorithm.getURI () +
                 ".  Got: " + ds.getDigestAlgorithm ().getURI ());
          }

        if (enc.signature_algorithm != null && enc.signature_algorithm != ds.getSignatureAlgorithm ())
          {
            bad ("Wrong signature algorithm.  Requested: " + enc.signature_algorithm.getURI () +
                 ".  Got: " + ds.getSignatureAlgorithm ().getURI ());
          }

        if (expected_sha1 != null &&
            (server_certificate_sha1 == null || !ArrayUtil.compare (server_certificate_sha1, expected_sha1)))
          {
            bad ("Server certificate SHA1");
          }

        if (cert_filters.size () > 0 && signer_certpath != null)
          {
            for (CertificateFilter cf : cert_filters)
              {
                if (cf.matches (signer_certpath, null, null))
                  {
                    return true;
                  }
              }
            bad ("Certificates does not match filter(s)");
          }

        // Success!
        return true;
      }

  }
