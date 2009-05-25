package org.webpki.asn1;

import java.util.*;
import java.io.*;
import java.security.cert.*;

public class ASN1Sequence extends Composite
  {
    public ASN1Sequence(BaseASN1Object[] components)
      {
        super(SEQUENCE, components);
      }
    
    public ASN1Sequence(Vector<BaseASN1Object> components)
      {
        super(SEQUENCE, components);
      }
    
    public ASN1Sequence(BaseASN1Object component)
      {
        super(SEQUENCE, new BaseASN1Object[]{ component });
      }
    
    ASN1Sequence(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    /**
     * Try to construct a X509Certificate from this sequence.
     */
    public X509Certificate x509Certificate() 
    throws IOException, CertificateException
      {
        // TODO !!!!!! This should be changed (moved and used more generally).
        if(blob == null)
          {
            blob = encode();
            blobOffset = 0;
          }
      
        return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                 new ByteArrayInputStream(blob, blobOffset, blob.length - blobOffset));
      }

    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("SEQUENCE");
        compositeString (s, prefix);
      }
  }
