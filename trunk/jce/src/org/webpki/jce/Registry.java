package org.webpki.jce;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import org.webpki.util.WrappedException;


/**
 * Key-store registry operations.  Unregistering is currently not implemented.
 */
public class Registry
  {
    public static void registerPropertyBagConsumer (Class<?> implementation_class) throws IOException
      {
        try
          {
            PropertyBagConsumer property_consumer = (PropertyBagConsumer)implementation_class.newInstance ();
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call AddPropertyBagConsumerSP(?, ?)}");
            stmt.setString (1, property_consumer.getPropertyBagDefinition ().getTypeURI ());
            stmt.setString (2, implementation_class.getCanonicalName ());
            stmt.execute ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        catch (InstantiationException ie)
          {
            throw new WrappedException (ie);
          }
        catch (IllegalAccessException iae)
          {
            throw new WrappedException (iae);
          }
      }


    public static void registerExtensionConsumer (Class<?> implementation_class) throws IOException
      {
        try
          {
            ExtensionConsumer extension_consumer = (ExtensionConsumer)implementation_class.newInstance ();
            Connection conn = KeyUtil.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call AddExtensionConsumerSP(?, ?)}");
            stmt.setString (1, extension_consumer.getTypeURI ());
            stmt.setString (2, implementation_class.getCanonicalName ());
            stmt.execute ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        catch (InstantiationException ie)
          {
            throw new WrappedException (ie);
          }
        catch (IllegalAccessException iae)
          {
            throw new WrappedException (iae);
          }
      }


    static class VPNBlah implements PropertyBagConsumer
      {
        static PropertyBagDefinition props = new PropertyBagDefinition ("http://example.com/VPN-blah");

        static
          {
            props.add ("Server");
          }


        public PropertyBagDefinition getPropertyBagDefinition () throws IOException
          {
            return props;
          }

        public String getName ()
          {
            return "Yeah";
          }

        public void parse (org.webpki.keygen2.CredentialDeploymentRequestDecoder.PropertyBag prop_bag, KeyDescriptor key_descriptor) throws IOException
          {
          }
      }


    static class EXTBlah implements ExtensionConsumer
      {
        public String getTypeURI ()
          {
            return "http://example.com/extblah";
          }

        public String getName ()
          {
            return "Yeah";
          }

        public void parse (byte[] data, KeyDescriptor key_descriptor) throws IOException
          {
          }
      }


    public static void fakeinit () throws IOException
      {
        registerPropertyBagConsumer (HOTPProvider.class);
        registerPropertyBagConsumer (TOTPProvider.class);
        registerPropertyBagConsumer (OCRAProvider.class);
        registerPropertyBagConsumer (VPNBlah.class);
        registerExtensionConsumer (EXTBlah.class);
        registerExtensionConsumer (InformationCardProvider.class);
      }

  }
