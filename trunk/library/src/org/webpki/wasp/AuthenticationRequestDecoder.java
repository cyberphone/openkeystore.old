package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestDecoder extends AuthenticationRequest
  {

    private String id;

    private String server_time;

    private String submit_url;

    private String cancel_url;                                                          // Optional

    private String[] languages;                                                         // Optional

    private int expires;                                                                // Optional

    private Vector<AuthenticationProfile> auth_profiles = new Vector<AuthenticationProfile> ();

    private Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter> ();  // Optional

    private AuthDocument main_document;

    private Vector<AuthDocument> embedded_objects = new Vector<AuthDocument> ();        // Optional

    private ServerCookie server_cookie;                                                 // Optional

    private ClientPlatformRequest client_platform_request;                              // Optional

    private XMLSignatureWrapper signature;                                              // Optional


    public class AuthenticationProfile
      {
        boolean signed_key_info;

        boolean extended_cert_path;

        String canonicalization_algorithm;

        String digest_algorithm;

        String signature_algorithm;

        AuthenticationProfile ()
          {
          }


        public boolean getSignedKeyInfo ()
          {
            return signed_key_info;
          }


        public boolean getExtendedCertPath ()
          {
            return extended_cert_path;
          }


        public CanonicalizationAlgorithms getCanonicalizationAlgorithm () throws IOException
          {
            return canonicalization_algorithm == null ? null : CanonicalizationAlgorithms.getAlgorithmFromURI (canonicalization_algorithm);
          }


        public HashAlgorithms getDigestAlgorithm () throws IOException
          {
            return digest_algorithm == null ? null : HashAlgorithms.getAlgorithmFromURI (digest_algorithm);
          }


        public SignatureAlgorithms getSignatureAlgorithm () throws IOException
          {
            return signature_algorithm == null ? null : SignatureAlgorithms.getAlgorithmFromURI (signature_algorithm);
          }

      }


    private void readAuthenticationProfile (DOMReaderHelper rd) throws IOException
      {
        rd.getNext (AUTHENTICATION_PROFILE_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        AuthenticationProfile ap = new AuthenticationProfile ();
        ap.signed_key_info = ah.getBooleanConditional (SIGNED_KEY_INFO_ATTR);

        ap.extended_cert_path = ah.getBooleanConditional (EXTENDED_CERT_PATH_ATTR);

        ap.canonicalization_algorithm = ah.getStringConditional (CN_ALG_ATTR);

        ap.digest_algorithm = ah.getStringConditional (DIGEST_ALG_ATTR);

        ap.signature_algorithm = ah.getStringConditional (SIGNATURE_ALG_ATTR);

        if ((ap.canonicalization_algorithm == null || CanonicalizationAlgorithms.testAlgorithmURI (ap.canonicalization_algorithm)) &&
            (ap.digest_algorithm == null || HashAlgorithms.testAlgorithmURI (ap.digest_algorithm)) &&
            (ap.signature_algorithm == null || SignatureAlgorithms.testAlgorithmURI (ap.signature_algorithm)))
          {
            auth_profiles.add (ap);
          }
      }


    public class AuthDocument implements MimeTypedObject
      {
        Object user_object;

        boolean referenced;
        byte[] data;
        String content_id;
        String mime_type;

        public String getContentID ()
          {
            return content_id;
          }

        public byte[] getData ()
          {
            referenced = true;
            return data;
          }

        public String getMimeType ()
          {
            return mime_type;
          }

        public boolean isReferenced ()
          {
            return referenced;
          }

        public Object getUserObject ()
          {
            return user_object;
          }

        public Object setUserObject (Object user_object)
          {
            return this.user_object = user_object;
          }

      }


    private AuthDocument readDocument (String elem, DOMReaderHelper rd, boolean has_content_id) throws IOException
      {
        AuthDocument doc = new AuthDocument ();
        rd.getNext (elem);
        doc.content_id = has_content_id ? rd.getAttributeHelper ().getString (CONTENT_ID_ATTR) : "cid:maindoc@example.com";
        rd.getChild ();
        if (rd.hasNext (BINARY_SUB_ELEM))
          {
            doc.data = rd.getBinary (BINARY_SUB_ELEM);
          }
        else
          {
            doc.data = rd.getString (TEXT_SUB_ELEM).getBytes ("UTF-8");
          }
        doc.mime_type = rd.getAttributeHelper ().getString (MIME_TYPE_ATTR);
        rd.getParent ();
        return doc;
      }


    public AuthenticationProfile[] getAuthenticationProfiles ()
      {
        return auth_profiles.toArray (new AuthenticationProfile[0]);
      }


    public CertificateFilter[] getCertificateFilters ()
      {
        return cert_filters.toArray (new CertificateFilter[0]);
      }


    public AuthDocument getMainDocument ()
      {
        return main_document;
      }


    public AuthDocument[] getEmbeddedObjects ()
      {
        return embedded_objects.toArray (new AuthDocument[0]);
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public String getID ()
      {
        return id;
      }


    public String getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public String getCancelURL ()
      {
        return cancel_url;
      }


    public ClientPlatformRequest getClientPlatformRequest ()
      {
        return client_platform_request;
      }


    public String[] getLanguages ()
      {
        return languages;
      }


    public int getExpires ()
      {
        return expires;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        id = ah.getString (ID_ATTR);

        server_time = ah.getString (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        cancel_url = ah.getStringConditional (CANCEL_URL_ATTR);

        languages = ah.getListConditional (LANGUAGES_ATTR);

        expires = ah.getIntConditional (EXPIRES_ATTR, -1);  // Default: no timeout and associated GUI

        rd.getChild ();
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the authentication profiles [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do
          {
            readAuthenticationProfile (rd);
          }
        while (rd.hasNext (AUTHENTICATION_PROFILE_ELEM));
        if (auth_profiles.isEmpty ())
          {
            throw new IOException ("No matching AuthenticationProfile found");
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (CERTIFICATE_FILTER_ELEM))
          {
            cert_filters.add (SignatureRequestDecoder.readCertificateFilter (rd));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the background view [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (BACKGROUND_VIEW_ELEM))
          {
            rd.getNext(BACKGROUND_VIEW_ELEM);
            rd.getChild ();

            /////////////////////////////////////////////////////////////////////////////////////////
            // Get the main document data [1]
            /////////////////////////////////////////////////////////////////////////////////////////
            main_document = readDocument (MAIN_DOCUMENT_SUB_ELEM, rd, false);

            /////////////////////////////////////////////////////////////////////////////////////////
            // Get the embedded object data [0..n]
            /////////////////////////////////////////////////////////////////////////////////////////
            while (rd.hasNext (EMBEDDED_OBJECT_SUB_ELEM))
              {
                embedded_objects.add (readDocument (EMBEDDED_OBJECT_SUB_ELEM, rd, true));
              }
            rd.getParent ();
          }
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional cookie-like data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional client platform request data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ClientPlatformRequest.CLIENT_PLATFORM_REQUEST_ELEM))
          {
            client_platform_request = ClientPlatformRequest.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (XMLSignatureWrapper.SIGNATURE_ELEM))
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext ());
          }
      }

  }
