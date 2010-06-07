package org.webpki.sks;

public class Property
  {
    String name;
    boolean writable;
    String value;
    
    Property (String name, boolean writable, String value)
      {
        this.name = name;
        this.writable = writable;
        this.value = value;
      }
    
    public String getName ()
      {
        return name;
      }
    
    public boolean isWritable ()
      {
        return writable;
      }
    
    public String getValue ()
      {
        return value;
      }
  }
