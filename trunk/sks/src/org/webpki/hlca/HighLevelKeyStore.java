package org.webpki.hlca;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;

import org.webpki.util.WrappedException;

import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethod;

import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SecureKeyStore;


/**
 * Base class for the universal keystore.  It must be extended by implementation classes
 * that either support asymmetric keys (PKI) or symmetric keys.
 */
abstract class HighLevelKeyStore
  {
    byte[] authorization;

    int key_handle;
   
    SecureKeyStore sks;
    
    KeyAttributes key_attributes;
    
    KeyProtectionInfo key_protection_info;

    private boolean shared_pins;
    
    private boolean auth_failed;

    private int pin_policy_id;               // 0 => no policy => no PIN
    
    KeyAuthorizationCallback key_auth_callback = new KeyAuthorizationCallback ()
      {
        public void setAuthorizationFailed ()
          {
            auth_failed = true;
          }
      };
      
    byte[] getAuthorization ()
      {
        return authorization;
      }
      
    public boolean authorizationFailed () throws IOException
      {
        return auth_failed;
      }

   
    HighLevelKeyStore (SecureKeyStore sks)
      {
        this.sks = sks;
      }


    abstract boolean wantAsymmetricKeys ();




    private String getPIN () throws IOException
      {
        throw new IOException ("Trusted GUI not implemented, request for \"" + key_id+ "\"");
      }



    /**
     * Sets the user/application authentication for a key (key handle) for cryptographic operations.
     * Note: this is a passive operation; the value isn't used until a cryptographic
     * operation to be performed using the SKS architecture.
     * @param key_id The id of the key.
     * @param pin A PIN or password value needed for using the key.  For keys that
     * are not PIN or password protected this value should be <code>null</code>.
     * @throws IOException if there are hard errors.
     */
    public void open (int key_id, String pin) throws IOException
      {
      }

  }
