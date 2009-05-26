package org.webpki.jce;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;

import org.webpki.util.WrappedException;

import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethods;


/**
 * Base class for the universal keystore.  It must be extended by implementation classes
 * that either support asymmetric keys (PKI) or symmetric keys.
 */
abstract class UniversalKeyStore
  {
    byte[] private_key_handle;

    byte[] secret_key_handle;

    String[] supported_algorithms;              // For symmetric keys only.  NULL = any

    X509Certificate[] cert_path;                // For asymmetric keys only

    int key_id;

    boolean cached_pin;

    int user_id;

    private boolean shared_pins;

    private int pin_policy_id;               // 0 => no policy => no PIN

   
    UniversalKeyStore (int user_id)
      {
        this.user_id = user_id;
      }


    abstract boolean wantAsymmetricKeys ();


    void testKey () throws IOException
      {
        if (key_id == 0)
          {
            throw new IOException ("open () MUST be called with a valid key_id!");
          }
      }


    void checkSymmetricKeyAndAlgorithm (String alg_uri) throws IOException
      {
        testKey ();
        if (secret_key_handle == null)
          {
            throw new IOException ("Symmetric key \"" + key_id + "\" unavailable due to a previous error (bad password?, already used?)");
          }
        if (supported_algorithms == null)
          {
            return;
          }
        for (String uri : supported_algorithms)
          {
            if (uri.equals (alg_uri))
              {
                return;
              }
          }
        throw new IOException ("Symmetric key \"" + key_id + "\" not usable with algorithm " + alg_uri);
      }


    void conditionalClose ()
      {
        if (!cached_pin)
          {
            close ();
          }
      }


    void checkPrivateKey () throws IOException
      {
        testKey ();
        if (private_key_handle == null)
          {
            throw new IOException ("Private key \"" + key_id + "\" unavailable due to a previous error (bad password?, already used?)");
          }
      }


    /**
     * Closes any open key (key handle).  This method should only be necessary to call for keys
     * that support PIN caching.
     */
    public void close ()
      {
        private_key_handle = null;
        secret_key_handle = null;
      }


    private String getPIN () throws IOException
      {
        throw new IOException ("Trusted GUI not implemented, request for \"" + key_id+ "\"");
      }


    private void setPINTryCount (int value) throws SQLException
      {
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("UPDATE USERKEYS SET PINTryCount=? WHERE " +
                                                         (shared_pins ? "PINPolicyID" : "KeyID") + "=?");
        pstmt.setInt (1, value);
        pstmt.setInt (2, shared_pins ? pin_policy_id : key_id);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
      }


    /**
     * Opens a key (key handle) for cryptographic operations.
     * @param key_id The internal database id of the key.
     * @param pin A PIN or password value needed for opening the key.  For keys that
     * are not PIN or password protected this value should be <code>null</code>.
     * @return <code>true</code> if successful else <code>false</code>.
     * @throws IOException if there are hard errors.
     */
    public boolean open (int key_id, String pin) throws IOException
      {
        close ();
        this.key_id = key_id;
        testKey ();
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            String wanted_key = wantAsymmetricKeys () ? "PrivateKey" : "SecretKey";
            String wanted_ext = wantAsymmetricKeys () ? "CertPath" : "SuppAlgs";
            PreparedStatement pstmt = conn.prepareStatement ("SELECT USERKEYS.PINPolicyID, " +
                                                                    "USERKEYS.PINTryCount, " +
                                                                    "USERKEYS.PINValue, " +
                                                                    "USERKEYS." + wanted_key + ", " +
                                                                    "USERKEYS." + wanted_ext + ", " +
                                                                    "PINPOLICIES.Format, " +
                                                                    "PINPOLICIES.RetryLimit, " +
                                                                    "PINPOLICIES.Grouping, " +
                                                                    "PINPOLICIES.CachingSupp, " +
                                                                    "PINPOLICIES.InputMeth " +
                                                             "FROM USERKEYS LEFT JOIN PINPOLICIES " +
                                                             "ON USERKEYS.PINPolicyID=PINPOLICIES.PINPolicyID " +
                                                             "WHERE USERKEYS.KeyID=? AND " +
                                                                   "USERKEYS." + wanted_key + " IS NOT NULL");
            pstmt.setInt (1, key_id);
            ResultSet rs = pstmt.executeQuery ();
            int pin_try_count = 0;
            int retry_limit = 0;
            PassphraseFormats format = null;
            InputMethods input_method = null;
            byte[] pin_value = null;
            if (rs.next ())
              {
                /*===============================================================*/
                /* If key has an associated PIN policy object get policy + data  */
                /*===============================================================*/
                if ((pin_policy_id = rs.getInt (1)) != 0)
                  {
                    pin_try_count = rs.getInt (2);
                    pin_value = rs.getBytes (3);
                    format = PassphraseFormats.values ()[rs.getInt (6)];
                    retry_limit = rs.getInt (7);
                    shared_pins = PINGrouping.SHARED.ordinal () == rs.getInt (8);
                    cached_pin = rs.getBoolean (9);
                    input_method = InputMethods.values ()[rs.getInt (10)];
                  }

                /*===============================================================*/
                /* Get/open handle to the actual key data of the selected key    */
                /*===============================================================*/
                if (wantAsymmetricKeys ())
                  {
                    private_key_handle = rs.getBytes (4);
                    cert_path = KeyUtil.restoreCertificatePathFromDB (rs.getBytes (5));
                  }
                else
                  {
                    secret_key_handle = rs.getBytes (4);
                    supported_algorithms = KeyUtil.getSupportedAlgorithms (rs.getString (5));
                  }
                rs.close ();
                pstmt.close ();
                conn.close ();
              }
            else
              {
                rs.close ();
                pstmt.close ();
                conn.close ();
                throw new IOException ("Missing key for \"" + key_id + "\"");
              }

            /*===============================================================*/
            /* Does this key require a PIN?  If not return success status    */
            /*===============================================================*/
            if (pin_policy_id == 0)
              {
                return true;
              }

            /*===============================================================*/
            /* Has this PIN-protected key already locked-up? => Soft failure */
            /*===============================================================*/
            if (pin_try_count == 0)
              {
                close ();
                return false;
              }

            /*===============================================================*/
            /* PIN (password) required.  Was it given?                       */
            /*===============================================================*/
            if (pin == null)
              {
                /*===============================================================*/
                /* No PIN given, is it OK to get it through the trusted GUI?     */
                /*===============================================================*/
                if (input_method == InputMethods.PROGRAMMATIC)
                  {
                    /*===============================================================*/
                    /* This key only supports programmatic PIN input!                */
                    /*===============================================================*/
                    close ();
                    throw new IOException ("PIN=null for \"" + key_id + "\"");
                  }

                /*===============================================================*/
                /* Call the the trusted GUI!                                     */
                /*===============================================================*/
                if ((pin = getPIN ()) == null)
                  {
                    /*===============================================================*/
                    /* User cancelled the PIN dialog => Soft failure                 */
                    /*===============================================================*/
                    close ();
                    return false;
                  }
              }
            else
              {
                /*===============================================================*/
                /* PIN given, is it OK to not use the trusted GUI?               */
                /*===============================================================*/
                if (input_method == InputMethods.TRUSTED_GUI)
                  {
                    /*===============================================================*/
                    /* This key only supports trusted PIN GUI input !                */
                    /*===============================================================*/
                    close ();
                    throw new IOException ("PIN <> null for \"" + key_id + "\"");
                  }
              }

            /*===============================================================*/
            /* Key is available, now check that the PIN is correct           */
            /*===============================================================*/
            if (ArrayUtil.compare (KeyUtil.getEncryptedPassphrase (pin, format), pin_value))
              {
                /*===============================================================*/
                /* PIN OK, but there may be a need to clear earlier errors       */
                /*===============================================================*/
                if (pin_try_count < retry_limit)
                  {
                    setPINTryCount (retry_limit);
                  }

                /*===============================================================*/
                /* Return success                                                */
                /*===============================================================*/
                return true;
              }

            /*===============================================================*/
            /* Bad PIN, close key and update the PIN error counter           */
            /*===============================================================*/
            close ();
            setPINTryCount (--pin_try_count);

            /*===============================================================*/
            /* Return [soft] failure                                         */
            /*===============================================================*/
            return false;
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
      }

  }
