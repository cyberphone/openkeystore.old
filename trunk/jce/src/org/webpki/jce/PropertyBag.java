package org.webpki.jce;

import java.io.IOException;

import java.util.HashMap;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.webpki.util.DebugFormatter;
import org.webpki.util.WrappedException;


/**
 * Property bag instance object.
 */
public class PropertyBag
  {
    String type_uri;

    int prop_bag_id;

    private HashMap<String,String> properties = new HashMap<String,String> ();

    private HashMap<String,Boolean> writable = new HashMap<String,Boolean> ();

    private PropertyBag () {}


    static PropertyBag getPropertyBag (int key_id, String type_uri) throws IOException
      {
        PropertyBag prop_bag = new PropertyBag ();
        prop_bag.type_uri = type_uri;
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT PROPERTIES.PropName, " +
                                                                    "PROPERTIES.PropValue, " +
                                                                    "PROPERTIES.Writable, " +
                                                                    "PROPERTIES.PropBagID " +
                                                             "FROM PROPERTIES, PROPERTYBAGS, TYPEREGISTRY " +
                                                             "WHERE PROPERTIES.PropBagID=PROPERTYBAGS.PropBagID AND " +
                                                                   "PROPERTYBAGS.TypeID=TYPEREGISTRY.TypeID AND " +
                                                                   "PROPERTYBAGS.KeyID=? AND TYPEREGISTRY.TypeURI=?");
            pstmt.setInt (1, key_id);
            pstmt.setString (2, type_uri);
            ResultSet rs = pstmt.executeQuery ();
            while (rs.next ())
              {
                String name = rs.getString (1);
                prop_bag.properties.put (name, rs.getString (2));
                prop_bag.writable.put (name, rs.getBoolean (3));
                prop_bag.prop_bag_id = rs.getInt (4);
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        return prop_bag.properties.isEmpty () ? null : prop_bag;
      }


    public String getTypeURI ()
      {
        return type_uri;
      }


    public String getString (String name) throws IOException
      {
        String value = properties.get (name);
        if (value == null)
          {
            throw new IOException ("No such property: " + name);
          }
        return value;
      }


    public int getInteger (String name) throws IOException
      {
        return Integer.parseInt (getString (name));
      }


    public boolean getBoolean (String name) throws IOException
      {
        return Boolean.valueOf (getString (name));
      }


    public byte[] getBytes (String name) throws IOException
      {
        return DebugFormatter.getByteArrayFromHex (getString (name));
      }


    public boolean isWritable (String name) throws IOException
      {
        getString (name);
        return writable.get (name);
      }


    public boolean isDefined (String name) throws IOException
      {
        return properties.get (name) != null;
      }


    public void setString (String name, String value) throws IOException
      {
        getString (name);
        if (!writable.get (name))
          {
            throw new IOException ("Property \"" + name + "\" is read-only");
          }
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("UPDATE PROPERTIES SET PropValue=? WHERE PropBagID=? AND PropName=?");
            pstmt.setString (1, value);
            pstmt.setInt (2, prop_bag_id);
            pstmt.setString (3, name);
            pstmt.executeUpdate ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
      }


    public void setInteger (String name, int value) throws IOException
      {
        setString (name, String.valueOf (value));
      }


    public void setBoolean (String name, boolean value) throws IOException
      {
        setString (name, String.valueOf (value));
      }

  }
