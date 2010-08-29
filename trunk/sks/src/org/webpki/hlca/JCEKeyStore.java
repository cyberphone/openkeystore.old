package org.webpki.hlca;

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
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Vector;
import java.util.Date;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import org.webpki.keygen2.PassphraseFormat;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sksimpl.softtoken.SKSReferenceImplementation;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/** Store wrapper
 *
 */
public class JCEKeyStore extends KeyStoreSpi
  {
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
    

    KeyAttributes findKey (String alias)
      {
        int key_handle = getInt (alias);
        EnumeratedKey ek = new EnumeratedKey ();
        try
          {
            while ((ek = sks.enumerateKeys (ek)).isValid ())
              {
                if (ek.getKeyHandle () == key_handle)
                  {
                    return sks.getKeyAttributes (key_handle);
                  }
              }
          }
        catch (SKSException e)
          {
            throw new RuntimeException (e);
          }
        return null;
      }

    /** Creates a new instance of JCEKeyStore */
    public JCEKeyStore () throws IOException
      {
      }
    

    /** Lists all the alias names of this keystore.*/
    @Override
    public Enumeration<String> engineAliases ()
      {
        return new EnumAliases ();
      }
    
    /** Enumeration of keys aliases*/
    class EnumAliases implements Enumeration<String>
      {
        EnumeratedKey ek = new EnumeratedKey ();
        
        EnumAliases ()
          {
          }
 
        public String nextElement ()
          {
            try
              {
                if ((ek = sks.enumerateKeys (ek)).isValid ())
                  {
                    return String.valueOf (ek.getKeyHandle ());
                  }
                throw new NoSuchElementException ("JCE");
              }
            catch (SKSException e)
              {
                throw new RuntimeException (e);
              }
          }
        
        public boolean hasMoreElements ()
          {
            try
              {
                return sks.enumerateKeys (ek).isValid ();
              } 
            catch (SKSException e)
              {
                throw new RuntimeException (e);
              }
          }
      }
    

    /**Checks if the given alias exists in this keystore.*/
    @Override
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
    @Override
    public void engineDeleteEntry (String alias) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }
    
    
    /**Returns the certificate associated with the given alias.
     * or null if the given alias does not exist or does not contain a certificate.*/
    @Override
    public Certificate engineGetCertificate (String alias)
      {
        KeyAttributes key_attributes = findKey (alias);
        if (key_attributes == null || key_attributes.isSymmetric ())
          {
            return null;
          }
        else
          {
            return key_attributes.getCertificatePath ()[0];
          }
      }
    

    /**Returns the (alias) name of the first keystore entry whose certificate matches the given certificate,
     * or null if no such entry exists in this keystore. */
    @Override
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
    

    /**Returns the certificate chain associated with the given alias.*/
    @Override
    public Certificate[] engineGetCertificateChain (String alias)
      {
        KeyAttributes key_attributes = findKey (alias);
        if (key_attributes == null || key_attributes.isSymmetric ())
          {
            return null;
          }
        else
          {
            Vector<Certificate> certchain = new Vector<Certificate> ();
            for (X509Certificate cert : key_attributes.getCertificatePath ())
              {
                certchain.add (cert);
              }
            return certchain.toArray (new Certificate[0]);
          }
      }
    

    /**Returns the creation date of the entry identified by the given alias.*/
    @Override
    public Date engineGetCreationDate (String alias)
      {
        int key_handle = getInt (alias);
        EnumeratedKey ek = new EnumeratedKey ();
        try
          {
            while ((ek = sks.enumerateKeys (ek)).isValid ())
              {
                if (ek.getKeyHandle () == key_handle)
                  {
                    EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                    while ((eps = sks.enumerateProvisioningSessions (eps, false)).isValid ())
                      {
                        if (eps.getProvisioningHandle () == ek.getProvisioningHandle ())
                          {
                            return eps.getClientTime ();
                          }
                      }
                  }
              }
          }
        catch (SKSException e)
          {
            throw new RuntimeException (e);
          }
        return null;
      }
    

    abstract class JCEKey
      {
        KeyProtectionInfo key_protection_info;
        
        KeyAttributes key_attributes;

        int key_handle;

        private byte[] authorization;
        
        byte[] getAuthorization ()
          {
            byte[] ret = authorization.clone ();
            if (!key_protection_info.getPINCachingFlag ())
              {
                authorization = null;
              }
            return ret;
          }
        
        SecureKeyStore getSKS ()
          {
            return sks;
          }

        JCEKey (String alias, 
                KeyAttributes key_attributes,
                byte[] authorization,
                KeyProtectionInfo key_protection_info)
          {
            this.key_handle = getInt (alias);
            this.key_attributes = key_attributes;
            this.authorization = authorization;
            this.key_protection_info = key_protection_info;
          }
      }

    
    class JCEPrivateKey extends JCEKey implements PrivateKey
      {
        static final long serialVersionUID = 1;

        
        JCEPrivateKey (String alias,
                       KeyAttributes key_attributes,
                       byte[] authorization,
                       KeyProtectionInfo key_protection_info) throws SKSException
          {
            super (alias, key_attributes, authorization, key_protection_info);
          }
       

       /**Returns the standard algorithm name for this key.*/
        @Override
        public String getAlgorithm ()
          {
            return "RSA";
          }
        

        /** NOT EXCTRACTIBLE : Returns null. 
         * Returns the key in its primary encoding format, or null if this key does not support encoding. */
        @Override
        public byte[] getEncoded ()
          {
            // not extractible
            return null;
          }
              

        @Override
        public String getFormat ()
          {
            return "VSEKey";
          } 
        
      }


    class JCESecretKey extends JCEKey implements SecretKey
      {
        static final long serialVersionUID = 1;


        JCESecretKey (String alias,
                      KeyAttributes key_attributes,
                      byte[] authorization,
                      KeyProtectionInfo key_protection_info) throws SKSException
          {
            super (alias, key_attributes, authorization, key_protection_info);
          }
        

        /**Returns the standard algorithm name for this key.*/
        @Override
        public String getAlgorithm ()
          {
            return "RAW";
          }
        

        /** NOT EXCTRACTIBLE : Returns null. 
         * Returns the key in its primary encoding format, or null if this key does not support encoding. */
        @Override
        public byte[] getEncoded ()
          {
            // not extractible
            return null;
          }
              

        @Override
        public String getFormat ()
          {
            return "VSEKey";
          } 
        
      }


    /* Gets a KeyStore.Entry for the specified alias with the specified protection parameter.*/
    //engineGetEntry(String alias, KeyStore.ProtectionParameter protParam)
    
    /**Returns the key associated with the given alias.*/
    @Override
    public Key engineGetKey (String alias, char[] password) throws UnrecoverableKeyException
      {
        KeyAttributes key_attributes = findKey (alias);
        if (key_attributes == null)
          {
            throw new UnrecoverableKeyException ("No key for alias: " + alias);
          }
        try
          {
            KeyProtectionInfo key_protection_info = sks.getKeyProtectionInfo (getInt (alias));
            byte[] authorization;
            if (password == null)
              {
                authorization = new byte[0];
              }
            else
              {
                authorization = String.valueOf (password).getBytes ("UTF-8");
                if (key_protection_info.isPINProtected () &&
                    key_protection_info.getPINFormat () == PassphraseFormat.BINARY)
                  {
                    authorization = DebugFormatter.getByteArrayFromHex (String.valueOf (password));
                  }
              }
            return key_attributes.isSymmetric () ?
                  new JCESecretKey (alias, key_attributes, authorization, key_protection_info)
                                                 :
                  new JCEPrivateKey (alias, key_attributes, authorization, key_protection_info);
          }
        catch (IOException e)
          {
            throw new RuntimeException (e);
          }
      }
    

    /**Returns true if the entry identified by the given alias was created by a
     * call to setCertificateEntry, or created by a call to setEntry with a
     * TrustedCertificateEntry.*/
    @Override
    public boolean engineIsCertificateEntry (String alias)
      {
        throw new RuntimeException (NOT_IMPLEMENTED);
      }
    

    /**Returns true if the entry identified by the given alias was created by a
     * call to setKeyEntry, or created by a call to setEntry with a
     * PrivateKeyEntry or a SecretKeyEntry.*/
    @Override
    public boolean engineIsKeyEntry (String alias)
      {
        return findKey (alias) != null;
      }
    

    /**Loads the keystore */
    @Override
    public void engineLoad (InputStream stream, char[] password) throws IOException
      {
        sks = ServiceLoader.load (SecureKeyStore.class).iterator ().next ();
        if (sks instanceof SKSReferenceImplementation)
          {
            if (stream == null || password == null)
              {
                throw new IOException ("stream or password was null");
              }
            try
              {
                byte[] data = ArrayUtil.getByteArrayFromInputStream (stream);
                System.arraycopy (arg0, arg1, arg2, arg3, arg4);
              }
          }
        else
          {
            if (stream != null || password == null)
              {
                throw new IOException ("param error, must be null, {userid}");
              }
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
      }
    

    /*public void engineLoad(KeyStore.LoadStoreParameter param)*/
    

    /**Assigns the given certificate to the given alias.*/
    @Override
    public void engineSetCertificateEntry (String alias, Certificate cert) throws KeyStoreException
      {
        throw new KeyStoreException ("Not implemented.");
      }

    
    /*engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)*/
    
    /**Assigns the given key (that has already been protected) to the given alias.*/
    @Override
    public void engineSetKeyEntry (String alias, byte[] key, Certificate[] chain) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }
    

    /** Assigns the given key to the given alias, protecting it with the given password.*/
    @Override
    public void engineSetKeyEntry (String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException
      {
        throw new KeyStoreException (NOT_IMPLEMENTED);
      }

    
    /**Retrieves the number of entries in this keystore.*/
    @Override
    public int engineSize ()
      {
        Enumeration<String> aliases = engineAliases ();
        int i = 0;
        while (aliases.hasMoreElements ())
          {
            i++;
            aliases.nextElement ();
          }
        return i;
      }
    
   /*public void engineStore (KeyStore.LoadStoreParameter param)*/
    
    @Override
    public void engineStore (OutputStream stream, char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException
      {
        throw new IOException (NOT_IMPLEMENTED);
      }

  }
