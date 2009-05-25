package org.webpki.pdf.test;


import java.io.IOException;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.JKSSignCertStore;

import org.webpki.pdf.PDFSigner;


public class Sign
  {

    public static void main (String argv[]) throws IOException
      {
        if (argv.length < 6 || 
            (!argv[0].equals ("c") && !argv[0].equals ("s")) ||
            (!argv[1].equals ("v") && !argv[1].equals ("i")) ||
            (!argv[2].equals ("p") && !argv[2].equals ("n")) ||
            (!argv[3].equals ("m") && !argv[3].equals ("e")))
          {
            System.out.println ("PDFSigner c|s v|i p|n m|e infile outfile [attachments]...\n\n" +
                                "   c = Certified document, s = Signed document\n" +
                                "   v = Visible signature, i = Invsible signature\n" +
                                "   p = Certificate path included, n = No path included (only signer certificate)\n" +
                                "   m = Marion Anderson is signing, e = Example.com is signing");
            System.exit (3);
          }
        JKSSignCertStore signer = new JKSSignCertStore (argv[3].equals ("m") ?
                                          DemoKeyStore.getMarionKeyStore () :
                                          DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        PDFSigner ds = new PDFSigner (signer);
                                                            
        if (argv[1].equals ("v"))
          {
            ds.setSignatureGraphics (true);
          }
        if (argv[2].equals ("p"))
          {
            ds.setExtendedCertPath (true);
          }
        for (int i = 6; i < argv.length; i++)
          {
            ds.addAttachment (argv[i], "Attachment #" + (i - 5), ArrayUtil.readFile (argv[i]));
          }
        ArrayUtil.writeFile (argv[5], ds.addDocumentSignature (ArrayUtil.readFile (argv[4]), argv[0].equals ("c")));
      }

  }
