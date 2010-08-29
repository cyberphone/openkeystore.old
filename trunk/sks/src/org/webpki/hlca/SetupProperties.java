package org.webpki.hlca;

import java.io.IOException;


/**
 * This interface is an optional part of classes that needs setup-parameters.
 */
public interface SetupProperties
  {
    public void init () throws IOException;
    
    public void setProperty (String name, String value) throws IOException;
    
    public String[] getProperties ();
 
  }
