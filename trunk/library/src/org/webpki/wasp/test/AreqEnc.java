package org.webpki.wasp.test;

import java.io.IOException;
import java.util.GregorianCalendar;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.JKSSignCertStore;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.wasp.AuthenticationRequestEncoder;
import org.webpki.wasp.AuthenticationResponseDecoder;

public class AreqEnc
  {

    private static void show ()
      {
        System.out.println ("AreqEnc outfile [options]\n" +
                            "  -W       simple 'Hello authentication world!'\n" +
                            "  -N       no background view\n" +
                            "  -F authfile  full round (all 4 steps)\n" +
                            "  -H       use sha256 as message digest\n" +
                            "  -B       use rsasha256 as signature method\n" +
                            "  -U       add server cookie data\n" +
                            "  -Q       request prefix REQ\n" +
                            "  -P       -F: RESP prefix\n" +
                            "  -A       full cert path\n" +
                            "  -D       signed keyinfo\n" +
                            "  -I       sign request\n" +
                            "  -T       set a fixed server time-stamp\n" +
                            "  -t       set a fixed client time-stamp\n" +
                            "  -t       set a fixed client time-stamp\n" +
                            "  -i       set a fixed reference ID\n" +
                            "  -f       set certificate filters\n" +
                            "  -l       set languages = eng\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length == 0) show ();
        boolean lang = false;
        String authfile = null;
        boolean reqprefix = false;
        boolean respprefix = false;
        boolean fixed_client_time = false;
        boolean fixed_server_time = false;
        boolean certpath = false;
        boolean simpledoc = false;
        boolean sha256DS = false;
        boolean rsasha256DS = false;
        boolean signrequest = false;
        boolean servercookie = false;
        boolean certflt = false;
        boolean signKI = false;
        boolean iddata = false;
        boolean background = true;
        for (int i = 1; i < args.length; i++)
          {
            if (args[i].equals ("-I")) signrequest = true;
            else if (args[i].equals ("-W")) simpledoc = true;
            else if (args[i].equals ("-N")) background = false;
            else if (args[i].equals ("-H")) sha256DS = true;
            else if (args[i].equals ("-B")) rsasha256DS = true;
            else if (args[i].equals ("-A")) certpath = true;
            else if (args[i].equals ("-D")) signKI = true;
            else if (args[i].equals ("-F"))
              {
                if (++i >= args.length || args[i].startsWith ("-"))
                  {
                    throw new IOException ("Bad -F option");
                  }
                authfile = args[i];
              }
            else if (args[i].equals ("-U")) servercookie = true;
            else if (args[i].equals ("-Q")) reqprefix = true;
            else if (args[i].equals ("-P")) respprefix = true;
            else if (args[i].equals ("-T")) fixed_server_time = true;
            else if (args[i].equals ("-t")) fixed_client_time = true;
            else if (args[i].equals ("-i")) iddata = true;
            else if (args[i].equals ("-f")) certflt = true;
            else if (args[i].equals ("-l")) lang = true;
            else show ();
          }
 
         
        AuthenticationRequestEncoder areqenc = null;
        if (simpledoc)
          {
            areqenc = new AuthenticationRequestEncoder ("example.com", "https://example.com/home");
            if (background)
              {
                areqenc.setMainDocument ("Hello authentication world!", "text/plain");
              }
          }
        else
          {
            areqenc = new AuthenticationRequestEncoder ("mybank.com", "https://secure.mybank.com/account");
            if (background)
              {
                String content_id_uri = areqenc.addEmbeddedObject (BankLogo.getGIFImage (), "image/gif");
                areqenc.setMainDocumentAsHTML ("<html><body><center><img src=\"" + content_id_uri + 
                                               "\"><p>Welcome to MyBank</center></body></html>");
              }
          }

        AuthenticationRequestEncoder.AuthenticationProfile ap = areqenc.addAuthenticationProfile ();

        ap.setExtendedCertPath (certpath);

        ap.setSignedKeyInfo (signKI);

        if (sha256DS)
          {
            ap.setDigestAlgorithm (HashAlgorithms.SHA256);
          }

        if (rsasha256DS)
          {
            ap.setSignatureAlgorithm (SignatureAlgorithms.RSA_SHA256);
          }

        if (certflt)
          {
            for (CertificateFilter cf : SreqEnc.createCertificateFilters ())
              {
                areqenc.addCertificateFilter (cf);
              }
          }

        if (iddata)
          {
            areqenc.setID ("I0762586222");
          }

        if (lang)
          {
            areqenc.setLanguages (new String[]{"eng"});
          }

        if (fixed_server_time)
          {
            areqenc.setServerTime (new GregorianCalendar (2005, 3, 10, 9, 30, 0).getTime());
          }

        if (servercookie)
          {
            areqenc.setServerCookie (SreqEnc.createServerCookie ());
          }

        if (reqprefix)
          {
            areqenc.setPrefix ("REQ");
          }
        if (signrequest)
          {
            JKSSignCertStore req_signer = new JKSSignCertStore (simpledoc ?
                                                         DemoKeyStore.getExampleDotComKeyStore ()
                                                                  :
                                                         DemoKeyStore.getMybankDotComKeyStore (), null);
            req_signer.setKey (null, DemoKeyStore.getSignerPassword ());
            areqenc.signRequest (req_signer);
          }

        byte[] data = areqenc.writeXML ();
        ArrayUtil.writeFile (args[0], data);
        XMLSchemaCache sc = new XMLSchemaCache ();
        sc.addWrapper (areqenc);
        sc.validate (data);

        if (authfile == null) return;

        // Simulate receival and transmit of data at the client

        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getMarionKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        AresEnc.test (args[0], authfile, signer, fixed_client_time, respprefix);

        // Receive by requesting service

        AuthenticationResponseDecoder aresdec = AresDec.test (authfile);
        aresdec.checkRequestResponseIntegrity (areqenc, null);

        ArrayUtil.writeFile (authfile, aresdec.writeXML ());

      }
  }
