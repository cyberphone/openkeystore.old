package org.webpki.xmldsig;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Date;

import java.security.SecureRandom;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;

import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.w3c.dom.Text;
import org.w3c.dom.Element;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1BitString;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.CertificateUtil;

public class XMLSignatureWrapper extends XMLObjectWrapper implements Serializable
  {
    private static final long serialVersionUID = 1L;

    public static final String XML_DSIG_NS_PREFIX = "ds";
    public static final String XML_DSIG11_NS_PREFIX = "ds11";

    public static final String XML_DSIG_NS       = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XML_DSIG11_NS     = "http://www.w3.org/2009/xmldsig11#";
    public static final String ENVELOPED_URI     = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    public static final String SIGNATURE_ELEM               = "Signature";
    public static final String X509_CERTIFICATE_ELEM        = "X509Certificate";
    public static final String X509_DATA_ELEM               = "X509Data";
    public static final String REFERENCE_ELEM               = "Reference";
    public static final String TRANSFORMS_ELEM              = "Transforms";
    public static final String TRANSFORM_ELEM               = "Transform";
    public static final String SIGNED_INFO_ELEM             = "SignedInfo";
    public static final String DIGEST_METHOD_ELEM           = "DigestMethod";
    public static final String DIGEST_VALUE_ELEM            = "DigestValue";
    public static final String CANONICALIZATION_METHOD_ELEM = "CanonicalizationMethod";
    public static final String SIGNATURE_METHOD_ELEM        = "SignatureMethod";
    public static final String SIGNATURE_VALUE_ELEM         = "SignatureValue";
    public static final String KEY_INFO_ELEM                = "KeyInfo";
    public static final String KEY_NAME_ELEM                = "KeyName"; // XML encryption only
    public static final String KEY_VALUE_ELEM               = "KeyValue";
    public static final String RSA_KEY_VALUE_ELEM           = "RSAKeyValue";
    public static final String EC_KEY_VALUE_ELEM            = "ECKeyValue";
    public static final String PUBLIC_KEY_ELEM              = "PublicKey";
    public static final String NAMED_CURVE_ELEM             = "NamedCurve";
    public static final String MODULUS_ELEM                 = "Modulus";
    public static final String EXPONENT_ELEM                = "Exponent";
    public static final String OBJECT_ELEM                  = "Object";
    public static final String X509_ISSUER_SERIAL_ELEM      = "X509IssuerSerial";
    public static final String X509_ISSUER_NAME_ELEM        = "X509IssuerName";
    public static final String X509_SERIAL_NUMBER_ELEM      = "X509SerialNumber";
    public static final String X509_SUBJECT_NAME_ELEM       = "X509SubjectName";

    public static final String URI_ATTR                     = "URI";
    public static final String ID_ATTR                      = "Id";
    public static final String ALGORITHM_ATTR               = "Algorithm";

    XMLObjectWrapper wrappedData;

    String x509IssuerName, x509SubjectName;

    BigInteger x509SerialNumber;

    X509Certificate[] certificates;

    PublicKey public_key;

    // Return only

    Element root;

    class ReferenceObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Element element;
        String id;
        CanonicalizationAlgorithms cn_alg;
        HashAlgorithms digest_alg;
        byte[] digest_val;
        boolean enveloped;

        ReferenceObject ()
          {
          }

        ReferenceObject (ReferenceObject o)
          {
            this.element = o.element;
            this.id = o.id;
            this.cn_alg = o.cn_alg;
            this.digest_alg = o.digest_alg;
            this.digest_val = o.digest_val;
            this.enveloped = o.enveloped;
          }
      }

    ReferenceObject reference_object_1;
    ReferenceObject reference_object_2;

    class SignedInfoObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Element element;
        CanonicalizationAlgorithms cn_alg;
        SignatureAlgorithms signature_alg;
        byte[] signature_val;
      }

    SignedInfoObject signedinfo_object;

    // Create only

    String envelope_id;

    String object_id;

    HashAlgorithms digest_algorithm;

    CanonicalizationAlgorithms canonicalization_algorithm;

    SignatureAlgorithms signature_algorithm;

    CanonicalizationAlgorithms transform_algorithm;

    Element SignedInfo_element;

    Text SignatureValue_node;
        
    Text SignedElement_Reference_node;

    Text KeyInfo_Reference_node;

    Element KeyInfo_element;

    Element Object_element;

    boolean KeyInfo_Reference_create;

    boolean pretty_printing;


    private static final String DUMMY_SIGNATURE = "dbp88TOVgyQ0xWyj4vFwMApimrk=";
    private static final String DUMMY_DIGEST    = "dbp88TOVgyQ0xWyj4vFwMApimrk=";

    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public XMLSignatureWrapper ()
      {
      }


    public String namespace()
      {
        return XML_DSIG_NS;
      }


    public String element()
      {
        return SIGNATURE_ELEM;
      }


    public void init () throws IOException                          
      {                                                                                
        addSchema ("w3c-xmldsig11.xsd");
        addSchema ("w3c-xmldsig.xsd");
      }                                                                                 


    public XMLObjectWrapper getWrappedData ()
      {
        return wrappedData;
      }


    public static PublicKey readPublicKey (DOMReaderHelper rd) throws IOException
      {
        PublicKey public_key = null;
        try
          {
            if (rd.hasNext (RSA_KEY_VALUE_ELEM))
              {
                rd.getNext (RSA_KEY_VALUE_ELEM);
                rd.getChild ();
                public_key = KeyFactory.getInstance ("RSA").generatePublic (new RSAPublicKeySpec (getRSA (rd, MODULUS_ELEM),
                                                                                                  getRSA (rd, EXPONENT_ELEM)));
              }
            else
              {
                rd.getNext (EC_KEY_VALUE_ELEM);
                rd.getChild ();
                rd.getNext (NAMED_CURVE_ELEM);
                public_key = KeyFactory.getInstance ("EC").generatePublic (
                    new X509EncodedKeySpec (
                      new ASN1Sequence (new BaseASN1Object[]
                        {
                          new ASN1Sequence (new BaseASN1Object[]
                            {
                              new ASN1ObjectID ("1.2.840.10045.2.1"),
                              new ASN1ObjectID (rd.getAttributeHelper ().getString (URI_ATTR).substring (8))
                            }),
                          new ASN1BitString (rd.getBinary (PUBLIC_KEY_ELEM))
                        }).encode ()));
              }
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
        rd.getParent ();
        return public_key;
      }


    public static X509Certificate[] readSortedX509DataSubset (DOMReaderHelper rd) throws IOException
      {
        return readSortedX509Data (rd, null);
      }


    private static X509Certificate[] readSortedX509Data (DOMReaderHelper rd, XMLSignatureWrapper sigwrap) throws IOException
      {
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        rd.getNext (X509_DATA_ELEM);
        rd.getChild ();

        while (rd.hasNext ())
          {
            if (rd.hasNext (X509_ISSUER_SERIAL_ELEM))
              {
                if (sigwrap == null)
                  {
                    throw new IOException ("Element \"" + X509_ISSUER_SERIAL_ELEM + "\" not allowed in this context");
                  }
                if (sigwrap.x509IssuerName != null)
                  {
                    throw new IOException ("This profile only allows one \"X509IssuerSerial\" element");
                  }
                rd.getNext (X509_ISSUER_SERIAL_ELEM);
                rd.getChild ();
                sigwrap.x509IssuerName = rd.getString (X509_ISSUER_NAME_ELEM);
                sigwrap.x509SerialNumber = rd.getBigInteger (X509_SERIAL_NUMBER_ELEM);
                rd.getParent ();
              }
            else if (rd.hasNext (X509_ISSUER_NAME_ELEM))
              {
                if (sigwrap == null)
                  {
                    throw new IOException ("Element \"" + X509_ISSUER_NAME_ELEM + "\" not allowed in this context");
                  }
                if (sigwrap.x509SubjectName != null)
                  {
                    throw new IOException ("This profile only allows one \"X509SubjectName\" element");
                  }
                sigwrap.x509SubjectName = rd.getString (X509_ISSUER_NAME_ELEM);
              }
            else if (rd.hasNext (X509_CERTIFICATE_ELEM))
              {
                certificates.addElement (CertificateUtil.getCertificateFromBlob (rd.getBinary (X509_CERTIFICATE_ELEM)));
              }
            else
              {
                throw new IOException ("Invalid element in \"X509Data\" for this profile encountered");
              }
          }
        if (certificates.isEmpty ()) throw new IOException ("No \"X509Certificate\" elements found");
        rd.getParent ();
        return CertificateUtil.getSortedPath (certificates.toArray (new X509Certificate [0]));
      }


    private ReferenceObject getReference (DOMReaderHelper rd) throws IOException
      {
        ReferenceObject ref = new ReferenceObject ();
        DOMAttributeReaderHelper aHelper = rd.getAttributeHelper ();
        rd.getNext (REFERENCE_ELEM);
        ref.id = aHelper.getString (URI_ATTR).substring (1);
        rd.getChild ();
        rd.getNext (TRANSFORMS_ELEM);
        rd.getChild ();
        rd.getNext (TRANSFORM_ELEM);
        String cn_alg = aHelper.getString (ALGORITHM_ATTR);
        if (cn_alg.equals (ENVELOPED_URI))
          {
            rd.getNext (TRANSFORM_ELEM);
            cn_alg = aHelper.getString (ALGORITHM_ATTR);
            ref.enveloped = true;
          }
        ref.cn_alg = CanonicalizationAlgorithms.getAlgorithmFromURI (cn_alg);
        if (rd.hasNext ()) throw new IOException ("Redundant \"Transforms\" elements");
        rd.getChild ();
        if (rd.hasNext ()) throw new IOException ("No \"Transform\" elements allowed");
        rd.getParent ();
        rd.getParent ();
        rd.getNext (DIGEST_METHOD_ELEM);
        ref.digest_alg = HashAlgorithms.getAlgorithmFromURI (aHelper.getString (ALGORITHM_ATTR));
        rd.getChild ();
        if (rd.hasNext ()) throw new IOException ("No \"DigestMethod\" elements allowed");
        rd.getParent ();
        ref.digest_val = rd.getBinary (DIGEST_VALUE_ELEM);
        rd.getParent ();
        return ref;
      }


    private static BigInteger getRSA (DOMReaderHelper rd, String elem) throws IOException
      {
        return new BigInteger (1, rd.getBinary (elem));
      }
    

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper aHelper = rd.getAttributeHelper ();

        signedinfo_object = new SignedInfoObject ();

        rd.getChild();
        
        signedinfo_object.element = rd.getNext (SIGNED_INFO_ELEM);
        rd.getChild ();
        rd.getNext (CANONICALIZATION_METHOD_ELEM);        
        signedinfo_object.cn_alg = CanonicalizationAlgorithms.getAlgorithmFromURI (aHelper.getString (ALGORITHM_ATTR));
        rd.getChild ();
        if (rd.hasNext ()) throw new IOException ("No \"CanonicalizationMethod\" elements allowed");
        rd.getParent();
        
        rd.getNext (SIGNATURE_METHOD_ELEM);
        signedinfo_object.signature_alg = SignatureAlgorithms.getAlgorithmFromURI (aHelper.getString (ALGORITHM_ATTR));
        rd.getChild ();
        if (rd.hasNext ()) throw new IOException ("No \"SignatureMethod\" elements allowed");
        rd.getParent ();

        reference_object_1 = getReference (rd);

        if (rd.hasNext (REFERENCE_ELEM))
          {
            reference_object_2 = getReference (rd);
          }

        if (rd.hasNext (REFERENCE_ELEM)) throw new IOException ("Max two \"Reference\" element are allowed by this implementation");
        rd.getParent ();

        signedinfo_object.signature_val = rd.getBinary (SIGNATURE_VALUE_ELEM);
        
        Element temp_el = rd.getNext (KEY_INFO_ELEM);
        if (aHelper.getStringConditional (ID_ATTR) != null)
          {
            String id = aHelper.getString (ID_ATTR);
            if (!reference_object_2.id.equals (id))
              {
                if (!reference_object_1.id.equals (id))
                  {
                    throw new IOException ("\"KeyInfo\" \"Id\" not found if any \"Reference\"");
                  }
                ReferenceObject temp = new ReferenceObject (reference_object_1);
                reference_object_1 = reference_object_2;
                reference_object_2 = temp;
              }
            reference_object_2.element = temp_el;
          }
        else if (reference_object_2 != null)
          {
            throw new IOException ("Missing \"Id\" attribute on \"KeyInfo\"");
          }
        rd.getChild ();
        if (rd.hasNext (X509_DATA_ELEM))
          {
            certificates = readSortedX509Data (rd, this);
          }
        else
          {
            rd.getNext (KEY_VALUE_ELEM);
            rd.getChild ();
            public_key = readPublicKey (rd);
            rd.getParent ();
          }
        if (rd.hasNext ()) throw new IOException ("Only one element allowed to \"KeyInfo\"");
        rd.getParent ();

        if (reference_object_1.enveloped)
          {
            if (rd.hasNext ()) throw new IOException ("Unexpected element");
          }
        else
          {
            reference_object_1.element = rd.getNext (OBJECT_ELEM);
        
            if(!reference_object_1.id.equals (aHelper.getString (ID_ATTR)))
              {
                throw new IOException ("Id mismatch (" + reference_object_1.id + ", " + aHelper.getString (ID_ATTR) + ").");
              }
       
            rd.getChild ();
        
            wrappedData = wrap (rd.getNext ());

            if (rd.hasNext ()) throw new IOException ("Only one \"Object\" element allowed in this profile");
          }
      }


    private Text createOneReference (DOMWriterHelper wr, String id, boolean add_enveloped_transform)
      {
        wr.addChildElement (REFERENCE_ELEM);
        wr.setStringAttribute (URI_ATTR, "#" + id);
        wr.addChildElement (TRANSFORMS_ELEM);
        if (add_enveloped_transform)
          {
            wr.addEmptyElement (TRANSFORM_ELEM);
            wr.setStringAttribute (ALGORITHM_ATTR, ENVELOPED_URI);
          }
        wr.addEmptyElement (TRANSFORM_ELEM);
        wr.setStringAttribute (ALGORITHM_ATTR, transform_algorithm.getURI ());
        wr.getParent();
        wr.addEmptyElement(DIGEST_METHOD_ELEM);
        wr.setStringAttribute (ALGORITHM_ATTR, digest_algorithm.getURI ());
        Text result = wr.addString (DIGEST_VALUE_ELEM, DUMMY_DIGEST);
        wr.getParent ();
        return result;
      }


    public static void addXMLSignatureNS (DOMWriterHelper wr)
      {
        wr.current ().setAttributeNS ("http://www.w3.org/2000/xmlns/", "xmlns:" + XML_DSIG_NS_PREFIX, XML_DSIG_NS);
      }


    public static void addXMLSignature11NS (DOMWriterHelper wr)
      {
        wr.current ().setAttributeNS ("http://www.w3.org/2000/xmlns/", "xmlns:" + XML_DSIG11_NS_PREFIX, XML_DSIG11_NS);
      }


    public static void writePublicKey (DOMWriterHelper wr, PublicKey public_key) throws IOException
      {
        if (public_key instanceof RSAPublicKey)
          {
            String old = wr.pushPrefix (XML_DSIG_NS_PREFIX);
            if (old == null || !old.equals (XML_DSIG_NS_PREFIX))
              {
                wr.addChildElementNS (XML_DSIG_NS, RSA_KEY_VALUE_ELEM);
              }
            else
              {
                wr.addChildElement (RSA_KEY_VALUE_ELEM);
              }
            wr.addBinary (MODULUS_ELEM, ((RSAPublicKey)public_key).getModulus ().toByteArray ());
            wr.addBinary (EXPONENT_ELEM, ((RSAPublicKey)public_key).getPublicExponent ().toByteArray ());
          }
        else
          {
            wr.pushPrefix (XML_DSIG11_NS_PREFIX);
            wr.addChildElementNS (XML_DSIG11_NS, EC_KEY_VALUE_ELEM);
            ASN1Sequence sequence = ParseUtil.sequence (DerDecoder.decode (((ECPublicKey)public_key).getEncoded ()), 2);
            wr.addEmptyElement (NAMED_CURVE_ELEM);
            wr.setStringAttribute (URI_ATTR, "urn:oid:" + ParseUtil.oid (ParseUtil.sequence (sequence.get(0), 2).get (1)).oid ());
            wr.addBinary (PUBLIC_KEY_ELEM, ParseUtil.bitstring (sequence.get (1)));
          }
        wr.getParent ();
        wr.popPrefix ();
      }


    public static void writeX509DataSubset (DOMWriterHelper wr, X509Certificate[] certificates) throws IOException
      {
        wr.pushPrefix (XML_DSIG_NS_PREFIX);
        writeX509Data (wr, null, certificates);
        wr.popPrefix ();
      }


    private static void writeX509Data (DOMWriterHelper wr, 
                                       XMLSignatureWrapper sigwrap, 
                                       X509Certificate[] certificates) throws IOException
      {
        if (sigwrap == null)
          {
            wr.addChildElementNS (XML_DSIG_NS, X509_DATA_ELEM);
          }
        else
          {
            wr.addChildElement (X509_DATA_ELEM);
            wr.addChildElement (X509_ISSUER_SERIAL_ELEM);
            wr.addString (X509_ISSUER_NAME_ELEM, sigwrap.x509IssuerName);
            wr.addObject (X509_SERIAL_NUMBER_ELEM, sigwrap.x509SerialNumber);
            wr.getParent ();
            if (sigwrap.x509SubjectName != null)
              {
                wr.addComment (" Signer DN: \"" + sigwrap.x509SubjectName + "\" ", true);
              }
          }

        for (X509Certificate certificate : certificates)
          {
            try
              {
                wr.addBinary (X509_CERTIFICATE_ELEM, certificate.getEncoded());
              }
            catch (GeneralSecurityException gse)
              {
                throw new IOException (gse.getMessage ());
              }
          }

        wr.getParent();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.setPrettyPrinting (pretty_printing);
        String base_id = Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());

        root = wr.initializeRootObject (XML_DSIG_NS_PREFIX);
        SignedInfo_element = wr.addChildElementNS (XML_DSIG_NS, SIGNED_INFO_ELEM);

        wr.addEmptyElement (CANONICALIZATION_METHOD_ELEM);
        wr.setStringAttribute (ALGORITHM_ATTR, canonicalization_algorithm.getURI ());

        wr.addEmptyElement (SIGNATURE_METHOD_ELEM);
        wr.setStringAttribute (ALGORITHM_ATTR, signature_algorithm.getURI ());
        object_id = object_id == null ? ("O." + base_id) : object_id;
        SignedElement_Reference_node = envelope_id == null ?
                     createOneReference (wr, object_id, false)
                                      :
                     createOneReference (wr, envelope_id, true);

        String key_id = envelope_id == null ? "K." + base_id : envelope_id + ".KeyInfo";
        if (KeyInfo_Reference_create)
          {
            KeyInfo_Reference_node = createOneReference (wr, key_id, false);
          }

        wr.getParent ();
        
        SignatureValue_node = wr.addString (SIGNATURE_VALUE_ELEM, DUMMY_SIGNATURE);
        
        KeyInfo_element = wr.addChildElementNS (XML_DSIG_NS, KEY_INFO_ELEM);
        if (KeyInfo_Reference_create)
          {
            wr.setStringAttribute (ID_ATTR, key_id);
          }
        
        if (public_key == null)
          {
            writeX509Data (wr, this, certificates);
          }
        else
          {
            wr.addChildElement (KEY_VALUE_ELEM);
            writePublicKey (wr, public_key);
            wr.getParent();
          }
        
        wr.getParent();
 
        if (envelope_id == null)
          {
            Object_element = wr.addChildElementNS (XML_DSIG_NS, OBJECT_ELEM);
            wr.setStringAttribute (ID_ATTR, object_id);
            wr.addWrapped (wrappedData);
          }
      }

  }
