package org.webpki.pdf.test;

import java.io.IOException;

import java.util.TimeZone;

import java.text.SimpleDateFormat;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.JKSCAVerifier;

import org.webpki.pdf.PDFVerifier;


public class Verify
  {

    public static void main (String argv[]) throws IOException
      {
        if (argv.length != 2 && argv.length != 1)
          {
            System.out.println ("PDFVerifier [n] infile\n\n      n = index of selected signature\n"+
                                                          "  (default is the whole-document signature)");
            System.exit (3);
          }
        JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);
        PDFVerifier pdf_verifier = new PDFVerifier (verifier);
        if (argv.length == 2)
          {
            pdf_verifier.selectSignatureByIndex (Integer.parseInt (argv[0]));
          }
        pdf_verifier.verifyDocumentSignature (ArrayUtil.readFile (argv[argv.length - 1]));
        System.out.println ("Signature name: " + pdf_verifier.getSignatureName ());
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        sdf.setTimeZone (TimeZone.getTimeZone ("UTC"));
        System.out.println ("Signature time: " + sdf.format (pdf_verifier.getSigningTime ()));
        System.out.println ("Signature covers whole document: " + pdf_verifier.getSignatureCoversWholeDocument ());
        System.out.println ("Document revision: " + pdf_verifier.getDocumentRevision ());
        System.out.println ("Document modified: " + pdf_verifier.getDocumentModifiedStatus ());
        System.out.println ("Signer certificate:\n" + verifier.getSignerCertificateInfo ().toString ());
        ArrayUtil.writeFile ("c:\\unsigned-file.pdf", pdf_verifier.getUnsignedDocument ());
      }

  }
