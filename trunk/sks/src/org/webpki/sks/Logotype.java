package org.webpki.sks;

import java.io.IOException;
import java.io.DataInputStream;

import java.util.HashMap;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.webpki.util.ImageData;
import org.webpki.util.WrappedException;

import org.webpki.keygen2.KeyGen2URIs;


/**
 * Logotype instance object.
 */
@SuppressWarnings("serial")
public class Logotype extends ImageData
  {
    private static HashMap<String,Logotype> default_logotypes = new HashMap<String,Logotype> ();

    private static void init (String type_uri, String resource)
      {
        try
          {
            DataInputStream dis = new DataInputStream (Logotype.class.getResourceAsStream (resource));
            byte[] data = new byte[dis.available()];
            dis.readFully (data);
            default_logotypes.put (type_uri, new Logotype (data, "image/" + resource.substring (resource.indexOf ('.') + 1), type_uri));
          }
        catch (IOException iox)
          {
          }
      }

    static
      {
        init (KeyGen2URIs.LOGOTYPES.APPLICATION, "noapplogo.gif");
        init (KeyGen2URIs.LOGOTYPES.CARD, "nocardlogo.png");
      }

    String type_uri;

    public String getTypeURI ()
      {
        return type_uri;
      }


    Logotype (byte[] data, String mime_type, String type_uri)
      {
        super (data, mime_type);
        this.type_uri = type_uri;
      }


    static Logotype getLogotype (int key_id, String type_uri) throws IOException
      {
        Logotype logotype = null;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT LOGOTYPES.ImageData, " +
                                                                    "LOGOTYPES.MimeType " +
                                                             "FROM LOGOTYPES, TYPEREGISTRY " +
                                                             "WHERE LOGOTYPES.TypeID=TYPEREGISTRY.TypeID AND " +
                                                                   "LOGOTYPES.KeyID=? AND TYPEREGISTRY.TypeURI=?");
            pstmt.setInt (1, key_id);
            pstmt.setString (2, type_uri);
            ResultSet rs = pstmt.executeQuery ();
            if (rs.next ())
              {
                logotype = new Logotype (rs.getBytes (1), rs.getString (2), type_uri);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException  (sqle);
          }
        return logotype;
      }


    public static Logotype getDefaultLogotype (String type_uri)
      {
        return default_logotypes.get (type_uri);
      }

  }
