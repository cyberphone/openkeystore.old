package org.webpki.hlca;

import java.io.IOException;

import java.util.Vector;

import java.sql.Connection;
import java.sql.Date;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.CallableStatement;
import java.sql.ResultSet;

import java.security.cert.X509Certificate;

import org.webpki.hlca.Extension;

import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;

import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.util.WrappedException;


/**
 * Key property descriptor.
 */
public class KeyDescriptor
  {
    public static enum OBJECT_TYPE {EXTENSIONS, PROPERTYBAGS, LOGOTYPES};
    
    KeyAttributes key_attributes;
    
    KeyProtectionInfo key_protection_info;

    int key_handle;


    KeyDescriptor (KeyAttributes key_attributes,
                   KeyProtectionInfo key_protection_info,
                   int key_handle)
      {
        this.key_attributes = key_attributes;
        this.key_protection_info = key_protection_info;
        this.key_handle = key_handle;
      }

    public Date getProvisioningDate ()
      {
        return provisioned;
      }


    public boolean isPINProtected ()
      {
        return key_protection_info.isPINProtected ();
      }


    public boolean isPINLocked ()
      {
        return pin_policy_id != 0 && pin_err_count == 0;
      }


    public boolean isPINSettable ()
      {
        return settable_pin;
      }


    public boolean isPUKLocked ()
      {
        return isPINLocked () && puk_err_count == 0;
      }


    public boolean hasCachedPIN ()
      {
        return pin_policy_id != 0 && cached_pin;
      }


    public boolean isAsymmetric ()
      {
        return !is_secret_key;
      }


    public boolean isSymmetric ()
      {
        return is_secret_key;
      }


    public int numberOfPINAttemptsLeft ()
      {
        return pin_err_count; 
      }


    public boolean isInBadPINMode ()
      {
        return pin_err_count < pin_retry_limit; 
      }


    public int numberOfPUKAttemptsLeft ()
      {
        return puk_err_count; 
      }


    public String[] getSupportedAlgorithms ()
      {
        return supported_algorithms;
      }


    public int getKeyID ()
      {
        return key_id;
      }


    public String getFriendlyName ()
      {
        return friendly_name;
      }


    public PassphraseFormat getPUKFormat ()
      {
        return puk_format;
      }


    public PassphraseFormat getPINFormat ()
      {
        return pin_format;
      }


    public boolean isExportable ()
      {
        return exportable;
      }


    public boolean isArchived ()
      {
        return archived;
      }


    public X509Certificate[] getCertificatePath () throws IOException
      {
        return KeyUtil.restoreCertificatePathFromDB (encoded_cert_path);
      }

    
    public String toString ()
      {
        StringBuffer s = new StringBuffer ("KeyDescriptor(");
        s.append(key_handle).append (')');
        if (getFriendlyName () != null)
          {
            s.append (" /Name=").append (getFriendlyName ());
          }
        s.append (" /KeyType=").append (is_secret_key ? "Symmetric" : "Asymmetric");
        if (isSymmetric ())
          {
            s.append ('[');
            if (getSupportedAlgorithms () == null)
              {
                s.append ("<unrestricted>");
              }
            else
              {
                boolean next = false;
                for (String alg : getSupportedAlgorithms ())
                  {
                    if (next)
                      {
                        s.append (' ');
                      }
                    else
                      {
                        next = true;
                      }
                    s.append (alg);
                  }
              }
            s.append (']');
          }
        s.append (" /PINProtected=").append (isPINProtected ());
        if (isPINProtected ())
          {
            if (isPINLocked ())
              {
                if (isPUKLocked ())
                  {
                    s.append (" /PUKLocked");
                  }
                else
                  {
                    s.append (" /PINLocked /PUKAttemptsleft=").append (numberOfPUKAttemptsLeft ());
                  }
              }
            else
              {
                s.append (" /PINAttemptsleft=").append (numberOfPINAttemptsLeft ());
              }
            s.append (" /PINSettable=").append (isPINSettable ());
            s.append (" /CachedPIN=").append (hasCachedPIN ());
            s.append (" /PINFormat=").append (getPINFormat ());
            s.append (" /PUKFormat=").append (getPUKFormat ());
          }
        return s.toString ();
      }


    public PropertyBag getPropertyBag (String type_uri) throws IOException
      {
        return PropertyBag.getPropertyBag (key_handle, type_uri);
      }


    public Extension getExtension (String type_uri) throws IOException
      {
        return Extension.getExtension (key_handle, type_uri);
      }


    public Logotype getLogotype (String type_uri) throws IOException
      {
        return Logotype.getLogotype (key_handle, type_uri);
      }


    public String[] enumerateAddOnObjectURIs (OBJECT_TYPE object_type) throws IOException
      {
        Vector<String> uris = new Vector<String> ();
        String sql = null;
        switch (object_type)
          {
            case EXTENSIONS:
              sql = "BL";
              break;

            case PROPERTYBAGS:
              sql = "";
              break;

            case LOGOTYPES:
              sql = "";
              break;
          }
        return uris.isEmpty () ? null : uris.toArray (new String[0]);
      }

  }
