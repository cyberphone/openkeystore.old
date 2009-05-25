package org.webpki.wasp.test;

import java.io.DataInputStream;
import java.io.IOException;


public class BankLogo
  {

    private byte[] get() throws IOException
      {
        DataInputStream dis = new DataInputStream (getClass().getResourceAsStream ("mini_banklogo.gif"));
        byte[] b = new byte[dis.available()];
        dis.readFully (b);
        return b;
      }


    public static byte[] getGIFImage () throws IOException
      {
        return new BankLogo ().get ();
      }

  }
