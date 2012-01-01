/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.wasp.test;

import org.webpki.util.StringUtil;
import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLCookie;

import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.wasp.AuthenticationRequestDecoder;


public class AreqDec
  {

    private static void show ()
      {
        System.out.println ("AreqDec inputfile [options]\n" +
                            "   -n   No object data output\n" +
                            "   -d   Debug\n");
        System.exit (3);
      }

    private static void print (String name, AuthenticationRequestDecoder.AuthDocument d, StringBuffer s) throws Exception
      {
        s.append ("\n" +name + ":\nURI=" + d.getContentID () +
                  "\nMimeType=" + d.getMimeType () + "\nValue=\n" +
                  new String (d.getData(), "UTF-8") + "\n");
      }

    static AuthenticationRequestDecoder test (String file, boolean outdata) throws Exception
      {

        byte[] data = ArrayUtil.readFile (file);

        XMLSchemaCache schema_cache = new XMLSchemaCache ();
        schema_cache.addWrapper (AuthenticationRequestDecoder.class);

        AuthenticationRequestDecoder areq = (AuthenticationRequestDecoder) schema_cache.parse (data);

        boolean signed = areq.isSigned ();

        JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);

        if (signed)
          {
            areq.verifySignature (verifier);
          }

        StringBuffer s = new StringBuffer ();

        for (AuthenticationRequestDecoder.AuthenticationProfile ap : areq.getAuthenticationProfiles ())
          {
            s.append ("\nAUTHPROF:");
            s.append ("\nSignedKeyInfo=" + ap.getSignedKeyInfo ());
            s.append ("\nExtendedCertPath=" + ap.getExtendedCertPath ());
            s.append ("\nCanonicalizationAlgorithm=" + ap.getCanonicalizationAlgorithm ());
            s.append ("\nDigestAlgorithm=" + ap.getDigestAlgorithm ());
            s.append ("\nSignatureAlgorithm=" + ap.getSignatureAlgorithm ());
            s.append ("\nAUTHPROF\n");
          }

        for (CertificateFilter cf : areq.getCertificateFilters ())
          {
            SreqDec.printcf (cf, s);
          }

        if (areq.getMainDocument () != null)
          {
            print ("MAIN_VIEW", areq.getMainDocument (), s);

            for (AuthenticationRequestDecoder.AuthDocument d : areq.getEmbeddedObjects ())
              {
                print ("EMBEDDED", d, s);
              }
          }

        if (areq.getServerCookie () != null)
          {
            s.append ("\nSERVERCOOKIE:");
            XMLCookie[] cookies = areq.getServerCookie ().getXMLCookies ();
            for (int i = 0; i < cookies.length; i++)
              {
                s.append ("\n[" + i + "]=\n").append (new String (cookies[i].getData (), "UTF-8"));
              }
            s.append ("\nSERVERCOOKIE\n");
          }

        s.append ("\nID=" + areq.getID () + "\n");

        if (areq.getLanguages () != null) s.append ("\nLanguages=" + StringUtil.tokenList (areq.getLanguages ()) + "\n");

        if (signed)
          {
            s.append ("\nSIGNATURE\n" + verifier.getSignerCertificateInfo ().toString () + "\nSIGNATURE");
          }

        if (outdata)
          {
            System.out.println (s.toString ());
          }
        return areq;
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length == 0) show ();
        boolean outdata = true;
        boolean debug = false;
        for (int i = 1; i < args.length; i++)
          {
            if (args[i].equals ("-n")) outdata = false;
            else if (args[i].equals ("-d")) debug = true;
            else show ();
          }
        if (debug) System.out.println ("Debug not available");  //Sorry...
        test (args[0], outdata);

      }

  }
