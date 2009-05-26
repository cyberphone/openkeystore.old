package org.webpki.jce;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.webpki.util.WrappedException;


/**
 * Extension instance object.
 */
public class Extension
  {
    String type_uri;

    byte[] data;


    private Extension () {}


    static Extension getExtension (int key_id, String type_uri) throws IOException
      {
        Extension extension = null;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT EXTENSIONS.ExtnData " +
                                                             "FROM EXTENSIONS, TYPEREGISTRY " +
                                                             "WHERE EXTENSIONS.TypeID=TYPEREGISTRY.TypeID AND " +
                                                                   "EXTENSIONS.KeyID=? AND TYPEREGISTRY.TypeURI=?");
            pstmt.setInt (1, key_id);
            pstmt.setString (2, type_uri);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                extension = new Extension ();
                extension.type_uri = type_uri;
                extension.data = rs.getBytes (1);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        return extension;
      }


    public String getTypeURI ()
      {
        return type_uri;
      }


    public byte[] getData ()
      {
        return data;
      }

  }
