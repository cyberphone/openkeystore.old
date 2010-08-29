package org.webpki.hlca;

import java.io.IOException;

import java.util.HashMap;

import org.webpki.keygen2.CredentialDeploymentRequestDecoder;

/**
 * Property bag definition class.  Typically used by PropertyBagConsumers.
 */
public class PropertyBagDefinition
  {
    boolean failed;

    private String type_uri;

    private int mandatory;

    class PropertyDefinition
      {
        String name;

        boolean writable;

        boolean optional;
      }

    @SuppressWarnings("unused")
    private PropertyBagDefinition () {}

    public PropertyBagDefinition (String type_uri)
      {
        this.type_uri = type_uri;
      }

    public String getTypeURI ()
      {
        return type_uri;
      }

    private HashMap<String,PropertyDefinition> property_definitions = new HashMap<String,PropertyDefinition> ();

    private void add (String name, boolean writable, boolean optional)
      {
        if (!optional)
          {
            mandatory++;
          }
        PropertyDefinition pdef = new PropertyDefinition ();
        pdef.name = name;
        pdef.writable = writable;
        pdef.optional = optional;
        if (property_definitions.put (name, pdef) != null)
          {
            failed = true;
          }
      }


    public void add (String name)
      {
        add (name, false, false);
      }


    public void addOptional (String name)
      {
        add (name, false, true);
      }


    public void addWritable (String name)
      {
        add (name, true, false);
      }


    public void addWritableOptional (String name)
      {
        add (name, true, true);
      }


    private void localBad (String error) throws IOException
      {
        throw new IOException (error + " in property-bag \"" + type_uri + "\"");
      }


    void parse (CredentialDeploymentRequestDecoder.PropertyBag prop_bag) throws IOException
      {
        int found_mandatory = 0;
        for (CredentialDeploymentRequestDecoder.Property prop : prop_bag.getProperties ())
          {
            PropertyDefinition pdef = property_definitions.get (prop.getName ());
            if (pdef == null)
              {
                localBad ("Unknown property \"" + prop.getName () + "\"");
              }
            if (!pdef.optional)
              {
                found_mandatory++;
              }
            if (prop.isWritable () && !pdef.writable)
              {
                localBad ("Property \"" + prop.getName () + "\" is read-only");
              }
          }
        if (mandatory > found_mandatory)
          {
            for (PropertyDefinition pdef : property_definitions.values ())
              {
                boolean found = false;
                for (CredentialDeploymentRequestDecoder.Property prop : prop_bag.getProperties ())
                  {
                    if (pdef.name.equals (prop.getName ()))
                      {
                        found = true;
                        break;
                      }
                  }
                if (!pdef.optional && !found)
                  {
                    localBad ("Property \"" + pdef.name + "\" is missing");
                  }
              }
          }
      }
    
  }
