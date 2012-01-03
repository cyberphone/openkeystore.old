package org.webpki.webutil.proxy;

import java.security.cert.X509Certificate;

import java.util.Vector;

public class UploadedTrustStore extends UploadPayloadObject
{
    private static final long serialVersionUID = 1L;
    
    Vector<X509Certificate> certs = new Vector<X509Certificate> ();
    
    public void addCertificate (X509Certificate cert)
    {
        certs.add (cert);
    }
    
    public X509Certificate[] getCertificates ()
    {
        return certs.toArray (new X509Certificate[0]);
    }
 
}
