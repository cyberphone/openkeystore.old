package org.webpki.jce;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.Vector;

import org.webpki.util.WrappedException;


/**
 * Meta data class for the universal keystore.
 */
public class KeyMetadataProvider
  {
    int user_id;

   
    public KeyMetadataProvider (int user_id)
      {
        this.user_id = user_id;
      }


    /**
     * Returns a description of the specific key.
     * Note that this method does not affect any opened keys.
     * @param key_id The internal database id of the key.
     * @return An instanciated <code>KeyDescriptor</code> object.
     * @throws IOException if there are hard errors.
     */
    public KeyDescriptor getKeyDescriptor (int key_id) throws IOException
      {
        KeyDescriptor kd = null;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement (KeyDescriptor.select + " AND USERKEYS.KeyID=?");
            pstmt.setInt (1, user_id);
            pstmt.setInt (2, key_id);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                kd = new KeyDescriptor (rs);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            if (kd == null)
              {
                throw new IOException ("No key found for id: \"" + key_id + "\"");
              }
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
        return kd;
      }


    /**
     * Returns an array of all user keys.
     * Note that this method does not affect any opened keys.
     * @return An array of <code>KeyDescriptor</code> objects.
     * @throws IOException if there are hard errors.
     */
    public KeyDescriptor[] getKeyDescriptors () throws IOException
      {
        try
          {
            Vector<KeyDescriptor> kds = new Vector<KeyDescriptor> ();
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement (KeyDescriptor.select);
            pstmt.setInt (1, user_id);
            ResultSet rs = pstmt.executeQuery ();
            while (rs.next ())
              {
                kds.add (new KeyDescriptor (rs));
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            return kds.toArray (new KeyDescriptor[0]);
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
      }

  }
