package org.webpki.crypto;

import java.util.Hashtable;

import java.security.cert.X509Certificate;


public class CertificateSelection
  {
    private Object provider;

    private Hashtable<String,X509Certificate> selection = new Hashtable<String,X509Certificate> ();


    public CertificateSelection (Object provider)
      {
        this.provider = provider;
      }


    public void addEntry (String key_alias, X509Certificate certificate)
      {
        selection.put (key_alias, certificate);
      }


    public Object getProvider ()
      {
        return provider;
      }


    public X509Certificate getCertificate (String key_alias)
      {
        return selection.get (key_alias);
      }


    public String[] getKeyAliases ()
      {
        return selection.keySet ().toArray (new String[0]);
      }

  }
