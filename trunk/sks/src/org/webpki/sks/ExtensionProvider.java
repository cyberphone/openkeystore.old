package org.webpki.sks;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.Vector;

import org.webpki.util.WrappedException;


/**
 * Extension base provider.
 */
public abstract class ExtensionProvider
  {
    Extension extension;

    int user_id;

    int key_id;
    
    SecureKeyStore sks;

    boolean symmetric_key_flag;

  
    public ExtensionProvider () // Only to be used used by the framework
      {
      }


    public static ExtensionProvider getExtensionProvider (int key_id, SecureKeyStore sks) throws IOException
      {
        ExtensionProvider[] exts = getExtensionProviders (sks, " AND USERKEYS.KeyID=" + key_id, null, null);
        return exts == null ? null : exts[0];
      }


    public static ExtensionProvider[] getExtensionProviders (SecureKeyStore sks, String type_uri, Class<?> application) throws IOException
      {
        return getExtensionProviders (sks, null, type_uri, application);
      }


    private static ExtensionProvider[] getExtensionProviders (SecureKeyStore sks, String sel_key_test, String sel_type_uri, Class<?> application) throws IOException
      {
        Vector<ExtensionProvider> providers = new Vector<ExtensionProvider> ();
        try
          {
            int user_id = 7;
            Connection conn = KeyUtil.getDatabaseConnection ();
            StringBuffer select = new StringBuffer ("SELECT USERKEYS.KeyID, " +
                                                           "USERKEYS.SecretKey IS NOT NULL, " +
                                                           "TYPEREGISTRY.TypeURI, " +
                                                           "EXTENSIONCONSUMERS.ImplClass " +
                                                    "FROM USERKEYS, EXTENSIONCONSUMERS, EXTENSIONS, TYPEREGISTRY " +
                                                    "WHERE USERKEYS.KeyID=EXTENSIONS.KeyID AND " +
                                                          "EXTENSIONS.TypeID=EXTENSIONCONSUMERS.TypeID AND " +
                                                          "EXTENSIONS.TypeID=TYPEREGISTRY.TypeID AND " +
                                                          "USERKEYS.UserID=?");
            if (sel_key_test != null)
              {
                select.append (sel_key_test);
              }
            if (sel_type_uri != null)
              {
                select.append (" AND TYPEREGISTRY.TypeURI=?");
              }
            PreparedStatement pstmt = conn.prepareStatement (select.toString ());

            pstmt.setInt (1, user_id);
            if (sel_type_uri != null)
              {
                pstmt.setString (2, sel_type_uri);
              }
            ResultSet rs = pstmt.executeQuery ();
            while (rs.next ())
              {
                ExtensionProvider ext_prov = null;
                int key_id = rs.getInt (1);
                boolean symmetric_key_flag = rs.getBoolean (2);
                String type_uri = rs.getString (3);
                String impl_class = rs.getString (4);
                Extension extension = Extension.getExtension (key_id, type_uri);
                try
                  {
                    Object object = Class.forName (impl_class).newInstance ();
                    if (application != null && !application.isInstance (object))
                      {
                        continue;
                      }
                    ext_prov = (ExtensionProvider) object;
                    ext_prov.init (extension, user_id, key_id, symmetric_key_flag);
                    providers.add (ext_prov);
                  }
                catch (InstantiationException ie)
                  {
                    throw new WrappedException (ie);
                  }
                catch (IllegalAccessException iae)
                  {
                    throw new WrappedException  (iae);
                  }
                catch (ClassNotFoundException cnfe)
                  {
                    throw new WrappedException  (cnfe);
                  }
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        return providers.isEmpty () ? null : providers.toArray (new ExtensionProvider[0]);
      }


    void init (Extension extension, int user_id, int key_id, boolean symmetric_key_flag)
      {
        this.extension = extension;
        this.user_id = user_id;
        this.key_id = key_id;
        this.symmetric_key_flag = symmetric_key_flag;
      }


    /**
     * Returns the key metadata descriptor associated with this ExtensionProvider instance.
     */
    public KeyDescriptor getKeyDescriptor () throws IOException
      {
        return new KeyMetadataProvider (sks).getKeyDescriptor (key_id);
      }

  }
