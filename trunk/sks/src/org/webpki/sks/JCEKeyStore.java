package org.webpki.sks;

import java.security.KeyStoreSpi;
import java.security.KeyStoreException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import java.util.Enumeration;
import java.util.ServiceLoader;
import java.util.Vector;
import java.util.Date;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import org.webpki.util.WrappedException;


/** Store wrapper
 *
 */
public class JCEKeyStore extends KeyStoreSpi
  {
    KeyDescriptor[] kds;
    
    SecureKeyStore sks;

    private static final String NOT_IMPLEMENTED = "Not implemented";
    
    private int getInt (char[] id)
      {
        int v = 0;
        for (char c : id)
          {
            v *= 10;
            if (c < '0' || c > '9')
              {
                throw new RuntimeException ("Not a number");
              }
            v += c - '0';
          }
        return v;
      }

    private int getInt (String id)
      {
        return getInt (id.toCharArray ());
      }
    

    KeyDescriptor findKey (String alias)
      {
        int key_id = getInt (alias);
        if (kds != null)
          {
            for (KeyDescriptor kd : kds)
              {
                if (kd.getKeyID () == key_id)
                  {
                    return kd;
                  }
              }
          }
        return null;
      }

    /** Creates a new instance of JCEKeyStore */
    public JCEKeyStore () throws IOException
      {
      }
    

    /** Lists all the alias names of this keystore.*/
    public Enumeration<String> engineAliases ()
      {
        return new EnumAliases ();
      }
    
    /** Enumeration of keys aliases*/
    class EnumAliases implements Enumeration<String>
      {
        int i;        
 
        public String nextElement ()
          {
            return hasMoreElements () ? String.valueOf (kds[i++].getKeyID ()) : null;
          }
        
        public boolean hasMoreElements ()
          {
            return kds != null && i < kds.length;
          }
      }
    

    /**Checks if the given alias exists in this keystore.*/
    public boolean engineContainsAlias (String alias)
      {
        for (Enumeration<String> aliases = engineAliases (); aliases.hasMoreElements ();)
          {
            if (aliases.nextElement ().equals (alias))
              {
                return true;
              }
          }
        return false;
      }
    

    /**Deletes the entry identified by the given alias from this keystore.*/
    public void engineDeleteEntry (String alias) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }
    
    
    /**Returns the certificate associated with the given alias.
     * or null if the given alias does not exist or does not contain a certificate.*/
    public Certificate engineGetCertificate (String alias)
      {
        KeyDescriptor kd = findKey (alias);
        if (kd == null || kd.isSymmetric ())
          {
            return null;
          }
        else
          {
            return getCertPath (kd)[0];
          }
      }
    

    /**Returns the (alias) name of the first keystore entry whose certificate matches the given certificate,
     * or null if no such entry exists in this keystore. */
    public String engineGetCertificateAlias (Certificate cert)
      {
        for (Enumeration<String> aliases = engineAliases (); aliases.hasMoreElements ();)
          {
            String alias = aliases.nextElement ();
            Certificate certks = engineGetCertificate (alias);
            if (certks != null && certks.equals (cert))
              {
                return alias;
              }
          }
        return null;
      }
    

    private X509Certificate[] getCertPath (KeyDescriptor kd)
      {
        try
          {
            return kd.getCertificatePath ();
          }
        catch (IOException ioe)
          {
            throw new WrappedException (ioe);
          }
      }


    /**Returns the certificate chain associated with the given alias.*/
    public Certificate[] engineGetCertificateChain (String alias)
      {
        KeyDescriptor kd = findKey (alias);
        if (kd == null || kd.isSymmetric ())
          {
            return null;
          }
        else
          {
            Vector<Certificate> certchain = new Vector<Certificate> ();
            for (X509Certificate cert : getCertPath (kd))
              {
                certchain.add (cert);
              }
            return certchain.toArray (new Certificate[0]);
          }
      }
    

    /**Returns the creation date of the entry identified by the given alias.*/
    public Date engineGetCreationDate (String alias)
      {
        /* ? possible ou pas ? je pense que non */
        return null;
      }
    

    class JCEPrivateKey extends HighLevelKeyStore implements PrivateKey
      {
        KeyDescriptor kd;

        String pin;

        static final long serialVersionUID = 1;

        
        JCEPrivateKey (KeyDescriptor kd, SecureKeyStore sks, char[] password)
          {
            super (sks);
            this.kd = kd;
            this.pin = password == null ? null : String.valueOf (password);
          }
       
        void open () throws IOException
          {
            open (kd.getKeyID (), pin);
          } 

        boolean wantAsymmetricKeys ()
         {
           return true;
         }


       /**Returns the standard algorithm name for this key.*/
        public String getAlgorithm ()
          {
            return "RSA";
          }
        

        /** NOT EXCTRACTIBLE : Returns null. 
         * Returns the key in its primary encoding format, or null if this key does not support encoding. */
        public byte[] getEncoded ()
          {
            // not extractible
            return null;
          }
              

        public String getFormat ()
          {
            return "VSEKey";
          } 
        
      }


    class JCESecretKey extends HighLevelKeyStore implements SecretKey
      {
        KeyDescriptor kd;
        int user_id;

        String pin;

        static final long serialVersionUID = 1;

        
        void open () throws IOException
          {
            open (kd.getKeyID (), pin);
          } 

        boolean wantAsymmetricKeys ()
         {
           return false;
         }


        JCESecretKey (KeyDescriptor kd, SecureKeyStore sks, char[] password)
          {
            super (sks);
            this.kd = kd;
            this.pin = String.valueOf (password);
          }
        

        /**Returns the standard algorithm name for this key.*/
        public String getAlgorithm ()
          {
            return "RAW";
          }
        

        /** NOT EXCTRACTIBLE : Returns null. 
         * Returns the key in its primary encoding format, or null if this key does not support encoding. */
        public byte[] getEncoded ()
          {
            // not extractible
            return null;
          }
              

        public String getFormat ()
          {
            return "VSEKey";
          } 
        
      }


    /* Gets a KeyStore.Entry for the specified alias with the specified protection parameter.*/
    //engineGetEntry(String alias, KeyStore.ProtectionParameter protParam)
    
    /**Returns the key associated with the given alias.*/
    public Key engineGetKey (String alias, char[] password) throws UnrecoverableKeyException
      {
        KeyDescriptor kd = findKey (alias);
        if (kd == null)
          {
            throw new UnrecoverableKeyException ("no key for alias: " + alias);
          }
        if (kd.isAsymmetric ())
          {
            return new JCEPrivateKey (kd, sks, password);
          }
        return new JCESecretKey (kd, sks, password);
      }
    

    /**Returns true if the entry identified by the given alias was created by a
     * call to setCertificateEntry, or created by a call to setEntry with a
     * TrustedCertificateEntry.*/
    public boolean engineIsCertificateEntry (String alias)
      {
        throw new RuntimeException (NOT_IMPLEMENTED);
      }
    

    /**Returns true if the entry identified by the given alias was created by a
     * call to setKeyEntry, or created by a call to setEntry with a
     * PrivateKeyEntry or a SecretKeyEntry.*/
    public boolean engineIsKeyEntry (String alias)
      {
        return findKey (alias) != null;
      }
    

    /**Loads the keystore */
    public void engineLoad (InputStream stream, char[] password) throws IOException
      {
        if (stream != null || password == null)
          {
            throw new IOException ("param error, must be null, {userid}");
          }
        sks = ServiceLoader.load (SecureKeyStore.class).iterator ().next ();
        if (sks instanceof SetupProperties)
          {
            SetupProperties setup = (SetupProperties) sks;
            for (String prop : setup.getProperties ())
              {
                if (prop.equals ("userid"))
                  {
                    setup.setProperty (prop, String.valueOf (getInt (password)));
                 }
              }
            setup.init ();
          }
        kds = new KeyMetadataProvider (sks).getKeyDescriptors ();
      }
    

    /*public void engineLoad(KeyStore.LoadStoreParameter param)*/
    

    /**Assigns the given certificate to the given alias.*/
    public void engineSetCertificateEntry (String alias, Certificate cert) throws KeyStoreException
      {
        throw new KeyStoreException ("Not implemented.");
      }

    
    /*engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)*/
    
    /**Assigns the given key (that has already been protected) to the given alias.*/
    public void engineSetKeyEntry (String alias, byte[] key, Certificate[] chain) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }
    

    /** Assigns the given key to the given alias, protecting it with the given password.*/
    public void engineSetKeyEntry (String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }

    
    /**Retrieves the number of entries in this keystore.*/
    public int engineSize ()
      {
        return kds == null ? 0 : kds.length;
      }
    
   /*public void engineStore (KeyStore.LoadStoreParameter param)*/
    
    public void engineStore (OutputStream stream, char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException
      {
        throw new IOException (NOT_IMPLEMENTED);
      }

  }
