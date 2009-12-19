package org.webpki.sks;

import java.io.IOException;


public interface SerialPortService 
  {
    public String getPortID () throws IOException;
    
    public int getBaudRate () throws IOException;
  }
