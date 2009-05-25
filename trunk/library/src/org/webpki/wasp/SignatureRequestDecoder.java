package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;

import java.math.BigInteger;

import org.w3c.dom.Element;

import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;

import static org.webpki.wasp.WASPConstants.*;


public class SignatureRequestDecoder extends SignatureRequest
  {

    private Vector<SignatureProfileDecoder> sign_profiles = new Vector<SignatureProfileDecoder> ();

    private Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter> ();  // Optional

    private DocumentReferences doc_refs;

    private DocumentData doc_data;

    private String id;

    private String server_time;

    private String submit_url;

    private String cancel_url;                                                          // Optional

    private ClientPlatformRequest client_platform_request;                              // Optional

    private String signature_gui_policy;                                                // Optional

    private String[] languages;                                                         // Optional

    private boolean copy_data;                                                          // Default: false

    private int expires;                                                                // Optional

    private ServerCookie server_cookie;                                                 // Optional

    private XMLSignatureWrapper signature;                                              // Optional

    private Attachment[] attachment_list;

    private EmbeddedObject[] embedded_object_list;


    static CertificateFilter readCertificateFilter (DOMReaderHelper rd) throws IOException
      {
        rd.getNext (CERTIFICATE_FILTER_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        byte[] sha1 = ah.getBinaryConditional (CF_SHA1_ATTR);
        String issuer = ah.getStringConditional (CF_ISSUER_ATTR);
        String subject = ah.getStringConditional (CF_SUBJECT_ATTR);
        String email_address = ah.getStringConditional (CF_EMAIL_ATTR);
        BigInteger serial = ah.getBigIntegerConditional (CF_SERIAL_ATTR);
        String policy_oid = ah.getStringConditional (CF_POLICY_ATTR);
        String[] scontainers = ah.getListConditional (CF_CONTAINERS_ATTR);
        KeyContainerTypes[] containers = null;
        if (scontainers != null)
          {
            containers = new KeyContainerTypes[scontainers.length];
            for (int q = 0; q < scontainers.length; q++)
              {
                boolean found = false;
                for (int i = 0; i < NAME2KEYCONTAINER.length; i++)
                  {
                    if (NAME2KEYCONTAINER[i].equals (scontainers[q]))
                      {
                        found = true;
                        containers[q] = KEYCONTAINER2NAME[i];
                        break;
                      }
                  }
                if (!found) throw new IOException ("Unknown container: " + scontainers[q]);
              }
          }
        CertificateFilter.KeyUsage key_usage = null;
        String key_usage_string = ah.getStringConditional (CF_KEY_USAGE_ATTR);
        if (key_usage_string != null)
          {
            key_usage = new CertificateFilter.KeyUsage ();
            for (int i = 0; i < key_usage_string.length (); i++)
              {
                switch (key_usage_string.charAt (i))
                  {
                    case '1':
                      key_usage.require (KeyUsageBits.values ()[i]);
                      break;

                    case '0':
                      key_usage.disAllow (KeyUsageBits.values ()[i]);
                      break;
                  }
              }
          }
        String ext_key_usage_oid = ah.getStringConditional (CF_EXT_KEY_USAGE_ATTR);
        return new CertificateFilter (sha1, issuer, subject, email_address, serial, policy_oid, containers, key_usage, ext_key_usage_oid);
      }


    public class BaseDocument implements MimeTypedObject
      {
        Object user_object;

        boolean referenced;
        byte[] data;
        String content_id;
        String mime_type;
        String meta_data;

        BaseDocument (DocumentReferences.Reference ref) throws IOException
          {
            if ((data = doc_data.getDocument (ref.content_id).data) == null)
              {
                if (doc_data.getDocument (ref.content_id) instanceof InternalDocument)
                  {
                    throw new IOException ("You MUST NOT use \"Internal\" data in a SignatureRequest");
                  }
                if (doc_data.getDocument (ref.content_id) instanceof DeletedDocument)
                  {
                    throw new IOException ("You MUST NOT use \"Deleted\" data in a SignatureRequest");
                  }
              }
            content_id = ref.content_id;
            mime_type = ref.mime_type;
            meta_data = ref.meta_data;
          }

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

        public String getMetaData ()
          {
            return meta_data;
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


    public class Attachment extends BaseDocument
      {
        boolean provider_originated;
        String description;
        String file;
        boolean must_access;

        Attachment (DocumentReferences.Reference ref) throws IOException
          {
            super (ref);
            provider_originated = ref.provider_originated;
            description = ref.description;
            file = ref.file;
            must_access = ref.must_access;
          }

        public boolean getProviderOriginated ()
          {
            return provider_originated;
          }

        public String getDescription ()
          {
            return description;
          }

        public String getFile ()
          {
            return file;
          }

        public boolean getMustAccess ()
          {
            return must_access;
          }

      }


    public class EmbeddedObject extends BaseDocument
      {
        EmbeddedObject (DocumentReferences.Reference ref) throws IOException
          {
            super (ref);
          }
      }


    public class Document extends BaseDocument
      {
        Document (DocumentReferences.Reference ref) throws IOException
          {
            super (ref);
          }
      }


   public SignatureProfileDecoder[] getSignatureProfilesDecoders ()
      {
        return sign_profiles.toArray (new SignatureProfileDecoder[0]);
      }


    public CertificateFilter[] getCertificateFilters ()
      {
        return cert_filters.toArray (new CertificateFilter[0]);
      }


    public Attachment[] getAttachments () throws IOException
      {
        if (attachment_list == null)
          {
            DocumentReferences.Reference[] ref_list = doc_refs.getAttachmentReferences ();
            attachment_list = new Attachment[ref_list.length];
            for (int i = 0; i < ref_list.length; i++)
              {
                attachment_list[i] = new Attachment (ref_list[i]);
              }
          }
        return attachment_list;
      }


    public EmbeddedObject[] getEmbeddedObjects () throws IOException
      {
        if (embedded_object_list == null)
          {
            DocumentReferences.Reference[] ref_list = doc_refs.getEmbeddedObjectReferences ();
            embedded_object_list = new EmbeddedObject[ref_list.length];
            for (int i = 0; i < ref_list.length; i++)
              {
                embedded_object_list[i] = new EmbeddedObject (ref_list[i]);
              }
          }
        return embedded_object_list;
      }


    public EmbeddedObject getEmbeddedObject (String content_id) throws IOException
      {
        return new EmbeddedObject (doc_refs.getReference (content_id));
      }


    private Document optDoc (DocumentReferences.Reference ref) throws IOException
      {
        return ref == null ? null : new Document (ref);
      }


    public Document getMainDocument () throws IOException
      {
        return optDoc (doc_refs.getMainDocument ());
      }


    public Document getProcessingDocument () throws IOException
      {
        return optDoc (doc_refs.getProcessingDocument ());
      }


    public Document getDetailDocument () throws IOException
      {
        return optDoc (doc_refs.getDetailDocument ());
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public DocumentData getDocumentData ()
      {
        return doc_data;
      }


    public DocumentReferences getDocumentReferences ()
      {
        return doc_refs;
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


    public String getSignatureGUIPolicy ()
      {
        return signature_gui_policy;
      }


    public String[] getLanguages ()
      {
        return languages;
      }


    public boolean getCopyData ()
      {
        return copy_data;
      }


    public int getExpires ()
      {
        return expires;
      }


    public DocumentSignatures getDocumentSignatures (HashAlgorithms digestAlgorithm, 
                                                     String canonicalizationAlgorithm) throws IOException
      {
        return new DocumentSignatures (digestAlgorithm, canonicalizationAlgorithm, doc_data);
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

        server_time = ah.getString (SERVER_TIME_ATTR);  // No point in converting to local presentation

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        cancel_url = ah.getStringConditional (CANCEL_URL_ATTR);

        signature_gui_policy = ah.getStringConditional (SIGNATURE_GUI_POLICY_ATTR);

        languages = ah.getListConditional (LANGUAGES_ATTR);

        copy_data = ah.getBooleanConditional (COPY_DATA_ATTR);

        expires = ah.getIntConditional (EXPIRES_ATTR, -1);  // Default: no timeout and associated GUI

        rd.getChild ();
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature profiles [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (SIGNATURE_PROFILES_ELEM);
        rd.getChild ();
        do
          {
            Element data = rd.getNext ();
            if (hasWrapper (data)) // We may NOT know the namespace (lax processing)
              {
                XMLObjectWrapper wrappedData = wrap (data);
                if (wrappedData instanceof SignatureProfileDecoder)
                  {
                    if (((SignatureProfileDecoder)wrappedData).hasSupportedParameters ())
                      {
                        sign_profiles.add ((SignatureProfileDecoder)wrappedData);
                      }
                  }
                else 
                  {
                    throw new IOException ("SignatureProfileDecoder instance expected but we got:" + wrappedData);
                  }
              }
          }
        while (rd.hasNext ());
        rd.getParent ();
        if (sign_profiles.isEmpty ())
          {
            throw new IOException ("No known signature profiles found!");
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (CERTIFICATE_FILTER_ELEM))
          {
            cert_filters.add (readCertificateFilter (rd));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the document references [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        doc_refs = DocumentReferences.read (rd);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the document data [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        doc_data = DocumentData.read (rd);
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
