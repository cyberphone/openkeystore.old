package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.EncryptionAlgorithms;

import static org.webpki.keygen2.KeyGen2Constants.*;


class XMLEncUtil
  {

    static void setEncryptionMethod (DOMWriterHelper wr, EncryptionAlgorithms algorithm) throws IOException
      {
        wr.addChildElement (ENCRYPTION_METHOD_ELEM);
        wr.setStringAttribute (XMLSignatureWrapper.ALGORITHM_ATTR, algorithm.getURI ());
        wr.getParent ();
      }


    static void setCipherData (DOMWriterHelper wr, byte[] key) throws IOException
      {
        wr.addChildElement (CIPHER_DATA_ELEM);
        wr.addBinary (CIPHER_VALUE_ELEM, key);
        wr.getParent ();
      }


    static void addXMLEncNS (DOMWriterHelper wr) throws IOException
      {
        wr.current ().setAttributeNS ("http://www.w3.org/2000/xmlns/", "xmlns:" + XML_ENC_NS_PREFIX, XML_ENC_NS);
      }


    static byte[] getCipherValue (DOMReaderHelper rd) throws IOException
      {
        rd.getNext (CIPHER_DATA_ELEM);
        rd.getChild ();
        byte[] data = rd.getBinary (CIPHER_VALUE_ELEM);
        rd.getParent ();
        return data;
      }


    static EncryptionAlgorithms getEncryptionMethod (DOMReaderHelper rd, EncryptionAlgorithms[] wanted_algorithms) throws IOException
      {
        rd.getNext (ENCRYPTION_METHOD_ELEM);
        String algo = rd.getAttributeHelper ().getString (XMLSignatureWrapper.ALGORITHM_ATTR);
        for (EncryptionAlgorithms enc_algo : wanted_algorithms)
          {
            if (algo.equals (enc_algo.getURI ()))
              {
                return enc_algo;
              }
          }
        throw new IOException ("Unexpected key encryption algorithm: " + algo);
      }



  }
