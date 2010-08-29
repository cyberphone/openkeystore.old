package org.webpki.hlca;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.Vector;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.WrappedException;

/**
 * OTP base provider.
 */
public abstract class OTPProvider
  {
    public static enum OTP_TYPES {TIME, EVENT, CHALLENGE_RESPONSE, TIME_AND_EVENT};

    PropertyBag property_bag;

    int key_handle;

    HighLevelKeyStore key_conn;

  
    OTPProvider () // Only used by the framework
      {
      }


    private static Vector<OTPProvider> getOTPProviders (SecureKeyStore sks, String sel_type_uri, OTP_TYPES sel_otp_type) throws IOException
      {
        Vector<OTPProvider> providers = new Vector<OTPProvider> ();
            ResultSet rs = pstmt.executeQuery ();
            Exception exception = null;
            while (rs.next ())
              {
                OTPProvider otp_prov = null;
                int key_id = rs.getInt (1);
                String type_uri = rs.getString (2);
                String impl_class = rs.getString (3);
                PropertyBag prop_bag = PropertyBag.getPropertyBag (key_id, type_uri);
                try
                  {
                    Object object = Class.forName (impl_class).newInstance ();
                    if (!(object instanceof OTPProvider))
                      {
                        continue;
                      }
                    otp_prov = (OTPProvider) object;
                    otp_prov.init (prop_bag, key_id);
                  }
                catch (InstantiationException ie)
                  {
                    exception = ie;
                    break;
                  }
                catch (IllegalAccessException iae)
                  {
                    exception = iae;
                    break;
                  }
                catch (ClassNotFoundException cnfe)
                  {
                    exception = cnfe;
                    break;
                  }
                if (sel_otp_type == null || sel_otp_type == otp_prov.getOTPTypeImplementation ())
                  {
                    providers.add (otp_prov);
                  }
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            if (exception != null)
              {
                throw new WrappedException (exception);
              }
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
        return providers;
      }


    void init (PropertyBag property_bag, int key_handle)
      {
        this.property_bag = property_bag;
        this.key_handle = key_handle;
      }

    /**
     * Opens the key associated with this OTP provider instance.
     */
    public void open (String pin) throws IOException
      {
        key_conn = hMacBottomOperation () ?
                                   new HmacProvider (key_conn.sks)
                                          :
                                   new SymKeyEncryptionProvider (key_conn.sks);
        key_conn.open (key_handle, pin);
      }

    private void open_test () throws IOException
      {
        if (key_conn == null)
          {
            throw new IOException ("\"open ()\" wasn't called");
          }
      }

    /**
     * Returns the type URI for this OTP provider instance.
     */
    public String getTypeURI () throws IOException
      {
        return getPropertyBagDefinition ().getTypeURI ();
      }

    /**
     * Returns the basic type of this OTP provider instance.
     */
    public OTP_TYPES getOTPType ()
      {
        return getOTPTypeImplementation ();
      }


    int getCycleImplementation () throws IOException
      {
        throw new IOException ("Only supported for time-based OTP providers");
      }


    int getChallengeLengthImplementation () throws IOException
      {
        throw new IOException ("Only supported for challenge-response-based OTP providers");
      }


    String generateImplementation (String challenge) throws IOException
      {
        return null;
      }


    String generateImplementation () throws IOException
      {
        throw new IOException ("Not supported for challenge-response-based OTP providers");
      }


    abstract PropertyBagDefinition getPropertyBagDefinition () throws IOException;

    abstract OTP_TYPES getOTPTypeImplementation ();

    abstract boolean hMacBottomOperation ();


    /**
     * Returns the time cycle in seconds for a time-based OTP provider instance.
     */
    public int getCycle () throws IOException
      {
        return getCycleImplementation ();
      }


    /**
     * Returns the number of digits needed for a challenge-response-based OTP provider instance.
     */
    public int getChallengeLength () throws IOException
      {
        return getChallengeLengthImplementation ();
      }


    /**
     * Returns the next OTP value.  For event-based OTP prividers the counter value is updated,
     * while time-based OTP providers simply return the value associated with the current time.
     */
    public String generate () throws IOException
      {
        open_test ();
        return generateImplementation ();
      }


    /**
     * Returns the OTP value for a challenge-response OTP provider instance.
     */
    public String generate (String challenge) throws IOException
      {
        open_test ();
        int digits = getChallengeLengthImplementation ();
        boolean ok = true;
        if (challenge == null || challenge.length () != digits)
          {
            ok = false;
          }
        else
          {
            for (int i = 0; i < digits; i++)
              {
                char c = challenge.charAt (i);
                if (c > '9' || c < '0')
                  {
                    ok = false;
                  }
              }
          }
        if (ok)
          {
            return generateImplementation (challenge);
          }
        throw new IOException ("Bad challenge data");
      }


    /**
     * Closes any open key (key handle).  This method should only be necessary to call for keys
     * that support PIN caching.
     */
    public void close () throws IOException
      {
        open_test ();
        key_conn.close ();
        key_conn = null;
      }


    /**
     * Returns the key metadata descriptor associated with this OTP provider instance.
     */
    public KeyDescriptor getKeyDescriptor () throws IOException
      {
        return new KeyMetadataProvider (key_conn.sks).getKeyDescriptor (key_handle);
      }

  }
