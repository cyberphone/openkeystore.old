package org.webpki.asn1;

import java.io.*;
import org.webpki.util.ArrayUtil;

/**
 * Command line utility for viewing ASN.1 structures.
 * Will output a tree view.
 */
public class DumpASN1 
  {
    static void printUsageAndExit(String error)
      {
        if(error != null)
          {
            System.out.println("");
            System.out.println(error);
            System.out.println("");          
          }
        System.out.println("Usage:");
        System.out.println("");
        System.out.println("  DumpASN1 [options] file");
        System.out.println("");
        System.out.println("    -x           Don't expand OCTET and BIT STRINGS");
        System.out.println("    -n           Don't show byte numbers");
        System.out.println("    -o nnn       Start parsing at decimal offset nnn");
        System.out.println("    -d file      Dump DER data to file");
        System.out.println("    -a file      Use alternate OID definition file");
        System.exit(0);
      }

    static int parseInt(String s)
      {
        try
          {
            return Integer.parseInt(s);
          }
        catch(NumberFormatException nfe)
          {
            printUsageAndExit("Malformed number " + s);
            return -1;
          }
      }

    
    public static void main(String[] args) throws Exception
      {
        if(args.length == 0) printUsageAndExit(null);
        
        int offset = 0;
        String oidfile = null;
        String outfile = null;
        boolean expand = true;
        boolean bytenum = true;
        String infile = null;
        
        for(int i = 0; i < args.length; i++)
          {
            String arg = args[i];
            if (arg.startsWith ("-"))
              {
                if (infile != null) printUsageAndExit ("unexpected option: " + arg);
                if (arg.equals ("-x"))
                  {
                    expand = false;
                  }
                else if (arg.equals ("-n"))
                  {
                    bytenum = false;
                  }
                else
                  {
                    if (++i >= args.length) printUsageAndExit ("Missing operand to option: " + arg);
                    String oper = args[i];
                    if (oper.startsWith ("-")) printUsageAndExit ("Bad operand to option: " + arg);
                    if (arg.equals ("-o"))
                      {
                        offset = parseInt(oper);
                      }
                    else if (arg.equals ("-d"))
                      {
                        outfile = oper;
                      }
                    else if (arg.equals ("-a"))
                      {
                        oidfile = oper;
                      }
                    else printUsageAndExit ("Unknown option: " + arg);
                  }
              }
            else
              {
                if (infile != null) printUsageAndExit ("Multiple input file: " + arg);
                infile = arg;
              }
          }
        if (infile == null) printUsageAndExit ("Missing input file!");

        if (oidfile != null) ASN1ObjectID.tryReadOIDNames(oidfile);
        
        BaseASN1Object o = DerDecoder.decode(ArrayUtil.readFile (infile), offset);
        
        System.out.println(o.toString (expand, bytenum));
        
        if(outfile != null)
          {
            FileOutputStream fos = new FileOutputStream(outfile);
            o.encode(fos);
            fos.close();
          }
      }
  }
