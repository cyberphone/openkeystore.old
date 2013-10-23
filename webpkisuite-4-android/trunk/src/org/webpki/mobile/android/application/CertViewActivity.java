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
package org.webpki.mobile.android.application;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import android.os.Bundle;

import android.webkit.WebView;

import android.app.Activity;

import android.content.Intent;

import org.webpki.android.asn1.ASN1ObjectID;

import org.webpki.android.crypto.CertificateInfo;
import org.webpki.android.crypto.CertificateUtil;

import org.webpki.android.util.HTMLEncoder;
import org.webpki.android.util.ArrayUtil;
import org.webpki.android.util.DebugFormatter;

import org.webpki.mobile.android.R;

public class CertViewActivity extends Activity
  {
    public static final String CERTIFICATE_BLOB = "cert_blob";

    private String niceDate (Date date)
      {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        sdf.setTimeZone (TimeZone.getTimeZone ("UTC"));
        return sdf.format (date);
      }


    private void add (StringBuffer s, String header, String data)
      {
        s.append ("<tr valign=\"middle\" bgcolor=\"#e0e0e8\"><td>").
        append (header).
        append ("</td><td><code>").
        append (data).
        append ("<code></td></tr>");
      }


    private void printURIs (StringBuffer s, String header, String[] inuris) throws IOException
      {
        if (inuris != null)
          {
            StringBuffer arg = new StringBuffer ();
            boolean break_it = false;
            for (String uri : inuris)
              {
                if (break_it)
                  {
                    arg.append ("<br>");
                  }
                else
                  {
                    break_it = true;
                  }
                arg.append (uri);
              }
            add (s, header, arg.toString ());
          }
      }
    
    
    private String formatCodeString (String hex_with_spaces)
      {
        StringBuffer dump = new StringBuffer ();
        for (char c : hex_with_spaces.toCharArray ())
          {
            if (c == '\n')
              {
                dump.append ("<br>");
              }
            else if (c == ' ')
              {
                dump.append ("&nbsp;");
              }
            else
              {
                dump.append (c);
              }
          }
        return dump.toString ();
      }

    private String binaryDump (byte[] binary, boolean show_text)
      {
        return formatCodeString (DebugFormatter.getHexDebugData (binary, show_text ? 16 : -16));
      }

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_cert_view);
        WebView log_view = (WebView) findViewById (R.id.certData);
        Intent intent = getIntent ();
        StringBuffer cert_text = new StringBuffer ("<html><body><table cellspacing=\"5\" cellpadding=\"5\">");
        try
          {
            CertificateInfo cert_info = new CertificateInfo (CertificateUtil.getCertificateFromBlob (intent.getByteArrayExtra (CERTIFICATE_BLOB)));
            add (cert_text, "Issuer", HTMLEncoder.encode (cert_info.getIssuer ()));
            add (cert_text, "Serial&nbsp;number", cert_info.getSerialNumber () + " (0x" + cert_info.getSerialNumberInHex () + ")");
            add (cert_text, "Subject", HTMLEncoder.encode (cert_info.getSubject ()));
            add (cert_text, "Valid&nbsp;from", niceDate (cert_info.getNotBeforeDate ()));
            add (cert_text, "Valid&nbsp;to", niceDate (cert_info.getNotAfterDate ()));
            String bc = cert_info.getBasicConstraints ();
            if (bc != null)
              {
                add (cert_text, "Basic&nbsp;constraints", bc);
              }
            printURIs (cert_text, "Key&nbsp;usage", cert_info.getKeyUsages ());
            String[] ext_key_usages = cert_info.getExtendedKeyUsage ();
            if (ext_key_usages != null)
              {
                for (int i = 0; i < ext_key_usages.length; i++)
                  {
                    ext_key_usages[i] = ASN1ObjectID.oidName (ext_key_usages[i]);
                  }
                printURIs (cert_text, "Extended&nbsp;key&nbsp;usage", ext_key_usages);
              }
            printURIs (cert_text, "Policy&nbsp;OIDs", cert_info.getPolicyOIDs ());
            printURIs (cert_text, "AIA&nbsp;CA&nbsp;issuers", cert_info.getAIACAIssuers ());
            printURIs (cert_text, "OCSP&nbsp;reponders", cert_info.getAIAOCSPResponders ());
            String fp = ArrayUtil.toHexString (cert_info.getCertificateHash (), 0, -1, true, ' ');
            add (cert_text, "SHA1&nbsp;fingerprint", fp.substring (0, 29) + "<br>" + fp.substring (29));
            add (cert_text, "Key&nbsp;algorithm", cert_info.getPublicKeyAlgorithm ());
            add (cert_text, "Public&nbsp;key", binaryDump (cert_info.getPublicKeyData (), false));
            cert_text.append ("</table>");
          }
        catch (Exception e)
          {
            cert_text = new StringBuffer ("<html><body><font color=\"red\">FAILED: ").append (e.getMessage ());
          }
        log_view.loadData (cert_text.append ("</body></html>").toString (), "text/html", null);
      }
  }
