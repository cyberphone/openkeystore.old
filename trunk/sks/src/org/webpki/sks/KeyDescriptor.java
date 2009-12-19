package org.webpki.sks;

import java.io.IOException;

import java.util.Vector;

import java.sql.Connection;
import java.sql.Date;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.CallableStatement;
import java.sql.ResultSet;

import java.security.cert.X509Certificate;

import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormats;

import org.webpki.util.WrappedException;


/**
 * Key property descriptor.
 */
public class KeyDescriptor
  {
    public static enum OBJECT_TYPE {EXTENSIONS, PROPERTYBAGS, LOGOTYPES};

    boolean exportable;

    boolean archived;

    int pin_policy_id;

    int pin_err_count;

    int pin_retry_limit;

    int puk_err_count;

    Date provisioned;

    boolean is_secret_key;

    boolean cached_pin;

    boolean settable_pin;

    String[] supported_algorithms;

    int key_id;

    String friendly_name;

    PassphraseFormats puk_format;

    PassphraseFormats pin_format;

    byte[] encoded_cert_path;

    @SuppressWarnings("unused")
    private KeyDescriptor () {}

    static final String select ="SELECT USERKEYS.Created, " +                   // 1
                                       "USERKEYS.Exportable, " +                // 2
                                       "USERKEYS.Archived, " +                  // 3
                                       "USERKEYS.CertPath, " +                  // 4
                                       "USERKEYS.PINPolicyID, " +               // 5
                                       "USERKEYS.PINTryCount, " +               // 6
                                       "USERKEYS.PINSettable, " +               // 7
                                       "USERKEYS.SecretKey IS NOT NULL, " +     // 8
                                       "USERKEYS.SuppAlgs, " +                  // 9
                                       "USERKEYS.KeyID, " +                     // 10
                                       "USERKEYS.FriendlyName, " +              // 11
                                       "PINPOLICIES.RetryLimit, " +             // 12
                                       "PINPOLICIES.CachingSupp, " +            // 13
                                       "PINPOLICIES.Format, " +                 // 14
                                       "PUKPOLICIES.Format, " +                 // 15
                                       "PUKPOLICIES.PUKTryCount " +             // 16
                                "FROM USERKEYS LEFT JOIN (PINPOLICIES CROSS JOIN PUKPOLICIES) " +
                                "ON USERKEYS.PINPolicyID=PINPOLICIES.PINPolicyID AND " +
                                   "PINPOLICIES.PUKPolicyID=PUKPOLICIES.PUKPolicyID " +
                                "WHERE USERKEYS.CertPath IS NOT NULL AND USERKEYS.UserID=?";

    public Date getProvisioningDate ()
      {
        return provisioned;
      }


    public boolean isPINProtected ()
      {
        return pin_policy_id != 0;
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


    public PassphraseFormats getPUKFormat ()
      {
        return puk_format;
      }


    public PassphraseFormats getPINFormat ()
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


    public boolean unlockKey (String puk_code) throws IOException
      {
        boolean success = false;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call UnlockKeySP(?, ?, ?, ?, ?)}");
            stmt.registerOutParameter (1, java.sql.Types.INTEGER);
            stmt.registerOutParameter (2, java.sql.Types.INTEGER);
            stmt.setInt (3, PINGrouping.SHARED.ordinal ());
            stmt.setInt (4, key_id);
            stmt.setBytes (5, KeyUtil.getPassphrase (puk_code, puk_format));
            stmt.execute ();
            int status = stmt.getInt (1);
            int value = stmt.getInt (2);
            stmt.close ();
            conn.close ();
            if (status == 0)
              {
                success = true;
                pin_err_count = value;
              }
            else if (status == 1)
              {
                puk_err_count = value;
              }
            else
              {
                throw new IOException ("Missing key \"" + key_id + "\" in database");
              }
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
        return success;
      }


    public void deleteKey () throws IOException
      {
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call DeleteKeySP(?)}");
            stmt.setInt (1, key_id);
            stmt.execute ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
      }


    public boolean changePIN (String old_pin, String new_pin) throws IOException
      {
        boolean success = false;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call PINChangeSP(?, ?, ?, ?, ?, ?)}");
            stmt.registerOutParameter (1, java.sql.Types.INTEGER);
            stmt.registerOutParameter (2, java.sql.Types.INTEGER);
            stmt.setInt (3, PINGrouping.SHARED.ordinal ());
            stmt.setInt (4, key_id);
            stmt.setBytes (5, KeyUtil.getPassphrase (old_pin, pin_format));
            stmt.setBytes (6, KeyUtil.getPassphrase (new_pin, pin_format));
            stmt.execute ();
            int status = stmt.getInt (1);
            int value = stmt.getInt (2);
            stmt.close ();
            conn.close ();
            if (status == 0)
              {
                success = true;
                pin_err_count = value;
              }
            else
              {
                throw new IOException ("Missing key \"" + key_id + "\" in database");
              }
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
        return success;
      }


    public String toString ()
      {
        StringBuffer s = new StringBuffer ("KeyDescriptor(");
        s.append(key_id).append (')');
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


    KeyDescriptor (ResultSet rs) throws IOException, SQLException
      {
        /*========================================================================*/
        /* Some always useful data                                                */
        /*========================================================================*/
        provisioned = rs.getDate (1);
        exportable = rs.getBoolean (2);
        archived = rs.getBoolean (3);
        encoded_cert_path = rs.getBytes (4);
        key_id = rs.getInt (10);
        friendly_name = rs.getString (11);
     
        /*========================================================================*/
        /* If this key has an associated PIN policy object, get relevant data     */
        /*========================================================================*/
        if ((pin_policy_id = rs.getInt (5)) != 0)
          {
            pin_err_count = rs.getInt (6);
            settable_pin = rs.getBoolean (7);
            pin_retry_limit = rs.getInt (12);
            cached_pin = rs.getBoolean (13);
            pin_format = PassphraseFormats.values ()[rs.getInt (14)];
            puk_format = PassphraseFormats.values ()[rs.getInt (15)];
            puk_err_count = rs.getInt (16);
          }
        /*========================================================================*/
        /* Piggybacked symmetric either has a set of supported algorithms or NULL */
        /*========================================================================*/
        if (is_secret_key = rs.getBoolean (8))
          {
            supported_algorithms = KeyUtil.getSupportedAlgorithms (rs.getString (9));
          }
      }


    public PropertyBag getPropertyBag (String type_uri) throws IOException
      {
        return PropertyBag.getPropertyBag (key_id, type_uri);
      }


    public Extension getExtension (String type_uri) throws IOException
      {
        return Extension.getExtension (key_id, type_uri);
      }


    public Logotype getLogotype (String type_uri) throws IOException
      {
        return Logotype.getLogotype (key_id, type_uri);
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
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement (sql);
            pstmt.setInt (1, key_id);
            ResultSet rs = pstmt.executeQuery ();
            while (rs.next ())
              {
                uris.add (rs.getString (1));
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        return uris.isEmpty () ? null : uris.toArray (new String[0]);
      }

  }
