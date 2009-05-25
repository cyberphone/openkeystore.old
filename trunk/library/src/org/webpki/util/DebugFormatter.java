package org.webpki.util;


import java.io.IOException;

public class DebugFormatter
  {
    private DebugFormatter ()
      {
      }

    private StringBuffer res = new StringBuffer (1000);

    private void put (char c)
      {
        res.append (c);
      }

    private void hex (int i)
      {
        if (i < 10)
          {
            put ((char)(i + 48));
          }
        else
          {
            put ((char)(i + 55));
          }
      }

    private void twohex (int i)
      {
        i &= 0xFF;
        hex (i / 16);
        hex (i % 16);
      }

    private void addrhex (int i)
      {
        if (i > 65535)
          {
            twohex (i / 65536);
            i %= 65536;
          }
        twohex (i / 256);
        twohex (i % 256);
      }

    private String toHexDebugData (byte indata[], int bytes_per_line)
      {
        int index = 0;
        int i = 0;
        if (indata.length == 0)
          {
            return "No data";
          }
        boolean only_data = false;
        if (bytes_per_line < 0)
          {
            bytes_per_line = -bytes_per_line;
            only_data = true;
          }
        while (index < indata.length)
          {
            if (index > 0)
              {
                put ('\n');
              }
            addrhex (index);
            put (':');
            int q = indata.length - index;
            if (q > bytes_per_line)
              {
                q = bytes_per_line;
              }
            for(i = 0; i < q; i++)
              {
                put (' ');
                twohex (indata[index + i]);
              }
            if (only_data)
              {
                index += q;
                continue;
              }
            while (i++ <= bytes_per_line)
              {
                put (' ');
                put (' ');
                put (' ');
              }
            put ('\'');
            for(i = 0; i < q; i++)
              {
                int c = (int) indata[index++];
                if (c < 32 || c >= 127)
                  {
                    put ('.');
                  }
                else
                  {
                    put ((char)c);
                  }
              }
            put ('\'');
            while (i++ < bytes_per_line)
              {
                put (' ');
              }
          }
        return res.toString ();
      }

    private String toHexString (byte indata[])
      {
        int i = 0;
        while (i < indata.length)
          {
            twohex (indata[i++]);
          }
        return res.toString ();
      }

    public static String getHexDebugData (byte indata[], int bytes_per_line)
      {
        return new DebugFormatter ().toHexDebugData (indata, bytes_per_line);
      }

    public static String getHexDebugData (byte indata[])
      {
        return getHexDebugData (indata, 16);
      }

    public static String getHexString (byte arr[])
      {
        return new DebugFormatter ().toHexString (arr);
      }

    public static int toHex (char c) throws IOException
      {
        if (c >= '0')
          {
            if (c <= '9') return c - '0';
            if (c >= 'a')
              {
                if (c <= 'f') return c - ('a' - 10);
              }
            if (c >= 'A')
              {
                if (c <= 'F') return c - ('A' - 10);
              }
          }
        throw new IOException ("Bad hexchar: " + c);
      }

    public static byte[] getByteArrayFromHex (String hex) throws IOException
      {
        int l = hex.length ();
        int bl;
        if (l == 0 || l % 2 != 0) throw new IOException ("Bad hexstring: " + hex);
        byte [] data = new byte[bl = l / 2];
        while (--bl >= 0)
          {
            data [bl] = (byte) (toHex (hex.charAt (--l)) + (toHex (hex.charAt (--l)) << 4));
          }
        return data;
      }


    /*##################################################################*/
    /*                                                                  */
    /*  Method: main                                                    */
    /*                                                                  */
    /*  Description: This is a command-line interface for testing only  */
    /*                                                                  */
    /*##################################################################*/

    public static void main (String args[]) throws IOException
      {
        if (args.length != 2 || !(args[0].equals("hex") || args[0].equals ("dump")))
          {
            System.out.println ("Usage: DebugFormatter hex|dump file \n");
            System.exit (0);
          }
        byte[] data = ArrayUtil.readFile (args[1]);
        System.out.print (args[0].equals ("dump") ? DebugFormatter.getHexDebugData (data) : DebugFormatter.getHexString (data));
      }

  }
