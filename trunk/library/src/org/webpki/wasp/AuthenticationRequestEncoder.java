/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.wasp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.util.Vector;
import java.util.Date;

import java.security.SecureRandom;

import org.w3c.dom.Document;

import org.webpki.util.MimeTypedObject;
import org.webpki.util.URLDereferencer;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.wasp.SignatureRequestEncoder;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestEncoder extends AuthenticationRequest
  {

    String id;

    Date server_time;

    String submit_url;

    String cancel_url;

    private String[] languages;

    private int expires;

    Vector<AuthenticationProfile> auth_profiles = new Vector<AuthenticationProfile> ();

    Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter> ();

    AuthReqDoc main_document;

    Vector<AuthReqDoc> embedded_objects = new Vector <AuthReqDoc> ();

    ServerCookie server_cookie;

    ClientPlatformRequest client_platform_request;


    private int next_content_id = 0;

    private String domain_id;

    private String prefix;  // Default: no prefix


    public class AuthenticationProfile
      {
        boolean signed_key_info;

        boolean extended_cert_path;

        CanonicalizationAlgorithms canonicalization_algorithm = CanonicalizationAlgorithms.C14N_EXCL;

        HashAlgorithms digest_algorithm = HashAlgorithms.SHA1;

        SignatureAlgorithms signature_algorithm = SignatureAlgorithms.RSA_SHA1;


        AuthenticationProfile ()
          {
          }


        public void setSignedKeyInfo (boolean flag)
          {
            this.signed_key_info = flag;
          }


        public void setExtendedCertPath (boolean flag)
          {
            this.extended_cert_path = flag;
          }


        public void setCanonicalizationAlgorithm (CanonicalizationAlgorithms canonicalization_algorithm)
          {
            this.canonicalization_algorithm = canonicalization_algorithm;
          }


        public void setDigestAlgorithm (HashAlgorithms digest_algorithm)
          {
            this.digest_algorithm = digest_algorithm;
          }


        public void setSignatureAlgorithm (SignatureAlgorithms signature_algorithm)
          {
            this.signature_algorithm = signature_algorithm;
          }


        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addEmptyElement (AUTHENTICATION_PROFILE_ELEM);
            if (signed_key_info)
              {
                wr.setBooleanAttribute (SIGNED_KEY_INFO_ATTR, true);
              }
            if (extended_cert_path)
              {
                wr.setBooleanAttribute (EXTENDED_CERT_PATH_ATTR, true);
              }
            if (canonicalization_algorithm != CanonicalizationAlgorithms.C14N_EXCL)
              {
                wr.setStringAttribute (CN_ALG_ATTR, canonicalization_algorithm.getURI ());
              }
            if (digest_algorithm != HashAlgorithms.SHA1)
              {
                wr.setStringAttribute (DIGEST_ALG_ATTR, digest_algorithm.getURI ());
              }
            if (signature_algorithm != SignatureAlgorithms.RSA_SHA1)
              {
                wr.setStringAttribute (SIGNATURE_ALG_ATTR, signature_algorithm.getURI ());
              }
          }
      }


    // Constructors

    @SuppressWarnings("unused")
    private AuthenticationRequestEncoder () {}


    public AuthenticationRequestEncoder (String domain_id, String submit_url, String cancel_url)
      {
        this.domain_id = domain_id;
        this.submit_url = submit_url;
        this.cancel_url = cancel_url;
      }


    public AuthenticationRequestEncoder (String domain_id, String submit_url)
      {
        this (domain_id, submit_url, null);
      }


    public AuthenticationProfile addAuthenticationProfile ()
      {
        AuthenticationProfile ap = new AuthenticationProfile ();
        auth_profiles.add (ap);
        return ap;
      }


    public CertificateFilter addCertificateFilter (CertificateFilter cf)
      {
        cert_filters.add (cf);
        return cf;
      }


    public void setID (String id)
      {
        this.id = id;
      }


    public void setServerTime (Date server_time)
      {
        this.server_time = server_time;
      }


    public void setLanguages (String[] languages)
      {
        this.languages = languages;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    private String getNextContentID ()
      {
        return "cid:d" + String.valueOf (next_content_id++) + "@" + domain_id;
      }


    private class AuthReqDoc
      {
        byte[] data;
        boolean binary_mode = true;
        String content_id;  // null for MainDocument
        String mime_type;
        boolean cdata_set;

        void write (DOMWriterHelper wr) throws IOException
          {
            if (binary_mode)
              {
                wr.addBinary (BINARY_SUB_ELEM, data);
              }
            else
              {
                try
                  {
                    String value = new String (data, "UTF-8");
                    int j = 0;
                    int q = 0;
                    while (j < data.length)
                      {
                        if (data[j++] == (byte)'<')
                          {
                            q++;
                          }
                      }
                    if (q > 5 || (cdata_set))
                      {
                        if (value.indexOf ('\r') >= 0)
                          {
                            throw new IOException ("DOS formatted text not allowed. Lines MUST end with \\n only");
                          }
                        wr.addCDATA (TEXT_SUB_ELEM, value);
                      }
                    else
                      {
                        wr.addString (TEXT_SUB_ELEM, value);
                      }
                  }
                catch (UnsupportedEncodingException e)
                  {
                    throw new IOException (e.toString ());
                  }
              }
            wr.setStringAttribute (MIME_TYPE_ATTR, mime_type);
          }
      }


    private AuthReqDoc createDocument (byte[] data, String content_id, String mime_type)
      {
        AuthReqDoc doc = new AuthReqDoc ();
        doc.content_id = content_id;
        doc.mime_type = mime_type;
        doc.data = data;
        int i = TEXT_TYPES.length;
        while (i-- > 0)
          {
            if (mime_type.equals (TEXT_TYPES[i]))
              {
                doc.binary_mode = false;
                doc.cdata_set = MARKUP_TYPES[i];
                break;
              }
          }
        return doc;
      }


    private void writeDocument (String elem, DOMWriterHelper wr, AuthReqDoc doc) throws IOException
      {
        wr.addChildElement (elem);
        if (doc.content_id != null)
          {
            wr.setStringAttribute (CONTENT_ID_ATTR, doc.content_id);
          }
        doc.write (wr);
        wr.getParent ();
      }



    public void setMainDocument (byte[] data, String mime_type) throws IOException
      {
        main_document = createDocument (data, null, mime_type);
      }


    public void setMainDocument (String data, String mime_type) throws IOException
      {
        setMainDocument (data.getBytes ("UTF-8"), mime_type);
      }


    public void setMainDocumentAsHTML (String utf8_encoded_html) throws IOException
      {
        setMainDocument (utf8_encoded_html, "text/html");
      }


    public void setMainDocumentFromMTO (MimeTypedObject mto) throws IOException
      {
        setMainDocument (mto.getData (), mto.getMimeType ());
      }


    public void setMainDocumentFromURL (String url) throws IOException
      {
        setMainDocumentFromMTO (new URLDereferencer (url));
      }


    public String addEmbeddedObject (byte[] data, String mime_type) throws IOException
      {
        AuthReqDoc doc = createDocument (data, getNextContentID (), mime_type);
        embedded_objects.add (doc);
        return doc.content_id;
      }


    public String addEmbeddedObject (String data, String mime_type) throws IOException
      {
        return addEmbeddedObject (data.getBytes ("UTF-8"), mime_type);
      }


    public String addEmbeddedObjectFromMTO (MimeTypedObject mto) throws IOException
      {
        return addEmbeddedObject (mto.getData (), mto.getMimeType ());
      }


    public String addEmbeddedObjectFromURL (String url) throws IOException
      {
        return addEmbeddedObjectFromMTO (new URLDereferencer (url));
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public ClientPlatformRequest createClientPlatformRequest ()
      {
        return client_platform_request = new ClientPlatformRequest ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        if (main_document == null && !embedded_objects.isEmpty ())
          {
            throw new IOException ("Missing MainDocument - MUST be set!");
          }

        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        if (id == null)
          {
            id = "_auth." + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom ().nextLong());
          }
        wr.setStringAttribute (ID_ATTR, id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        if (cancel_url != null)
          {
            wr.setStringAttribute (CANCEL_URL_ATTR, cancel_url);
          }

        if (languages != null)
          {
            wr.setListAttribute (LANGUAGES_ATTR, languages);
          }

        if (expires > 0)
          {
            wr.setIntAttribute (EXPIRES_ATTR, expires);
          }

        //////////////////////////////////////////////////////////////////////////
        // Authentication profiles
        //////////////////////////////////////////////////////////////////////////
        if (auth_profiles.isEmpty ())
          {
            addAuthenticationProfile ();
          }
        for (AuthenticationProfile ap : auth_profiles)
          {
            ap.write (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        for (CertificateFilter cf : cert_filters)
          {
            SignatureRequestEncoder.writeCertificateFilter (wr, cf);
          }

        //////////////////////////////////////////////////////////////////////////
        // Optional background view
        //////////////////////////////////////////////////////////////////////////
        if (main_document != null)
          {
            wr.addChildElement (BACKGROUND_VIEW_ELEM);

            //////////////////////////////////////////////////////////////////////
            // Main document
            //////////////////////////////////////////////////////////////////////
            writeDocument (MAIN_DOCUMENT_SUB_ELEM, wr, main_document);

            //////////////////////////////////////////////////////////////////////
            // Optional embedded objects
            //////////////////////////////////////////////////////////////////////
            for (AuthReqDoc doc : embedded_objects)
              {
                writeDocument (EMBEDDED_OBJECT_SUB_ELEM, wr, doc);
              }
            wr.getParent ();
          }

        //////////////////////////////////////////////////////////////////////////
        // Optional "server cookie"
        //////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform request"
        //////////////////////////////////////////////////////////////////////////
        if (client_platform_request != null)
          {
            client_platform_request.write (wr);
          }
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, id);
      }

  }
