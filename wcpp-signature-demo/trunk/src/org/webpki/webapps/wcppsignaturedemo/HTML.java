/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.wcppsignaturedemo;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.ExtendedKeyUsages;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;
import org.webpki.util.HTMLEncoder;
import org.webpki.util.ISODateTime;

public class HTML implements BaseProperties
  {
    static final int SIGNATURE_WINDOW_WIDTH            = 800;
    static final int SIGNATURE_WINDOW_HEIGHT           = 600;
    static final int SIGNATURE_LOADING_SIZE            = 48;
    static final int SIGNATURE_DIV_HORIZONTAL_PADDING  = 6;
    static final int SIGNATURE_DIV_VERTICAL_PADDING    = 5;
    static final String SIGNATURE_BORDER_COLOR         = "#306754";
    static final String SIGNATURE_DIALOG_COLOR         = "#F8F8F8";
    static final int SIGNATURE_PAN_PADDING_TOP         = 5;
    static final int SIGNATURE_PAN_PADDING_BOTTOM      = 10;
    static final int SIGNATURE_CARD_HORIZ_GUTTER       = 20;
    static final int SIGNATURE_CARD_RIGHT_MARGIN       = 30;
    static final int SIGNATURE_CARD_TOP_POSITION       = 25;
    static final int SIGNATURE_BUTTON_HORIZ_MARGIN     = 18;
    
    static final int PIN_MAX_LENGTH                  = 20;
    static final int PIN_FIELD_SIZE                  = 8;

    static final int SIGNATURE_TIMEOUT_INIT            = 5000;
    
    static final String FONT_VERDANA = "Verdana,'Bitstream Vera Sans','DejaVu Sans',Arial,'Liberation Sans'";
    static final String FONT_ARIAL = "Arial,'Liberation Sans',Verdana,'Bitstream Vera Sans','DejaVu Sans'";
    
    static final String HTML_INIT = 
        "<!DOCTYPE html>"+
        "<html><head><meta charset=\"UTF-8\"><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
//        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
        "<title>WebCrypto++ Signature Demo</title>"+
        "<style type=\"text/css\">html {overflow:auto}\n"+
        ".tftable {border-collapse:collapse}\n" +
        ".tftable th {font-size:10pt;background:" +
          "linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);" +
          "border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color:#a9a9a9;" +
          "text-align:center;font-family:" + FONT_ARIAL + "}\n" +
        ".tftable tr {background-color:#FFFFE0}\n" +
        ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;font-family:" + FONT_ARIAL + "}\n" +
        "body {font-size:10pt;color:#000000;font-family:" + FONT_VERDANA + ";background-color:white}\n" +
        "a {font-weight:bold;font-size:8pt;color:blue;font-family:" + FONT_ARIAL + ";text-decoration:none}\n" +
        "td {font-size:8pt;font-family:" + FONT_VERDANA + "}\n" +
        ".quantity {text-align:right;font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".updnbtn {vertical-align:middle;text-align:center;font-weight:normal;font-size:8px;font-family:" + FONT_VERDANA + ";margin:0px;border-spacing:0px;padding:2px 3px 2px 3px}\n" +
        ".headline {font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "}\n";
    
    static String getIframeHTML () throws IOException
      {
        return "<iframe src=\"" +
               SignatureDemoService.issuer_url +
               "/signatureframe\" style=\"width:" + SIGNATURE_WINDOW_WIDTH + 
               "px;height:" + SIGNATURE_WINDOW_HEIGHT + 
               "px;border-width:1px;border-style:solid;border-color:" +
               SIGNATURE_BORDER_COLOR + 
               ";box-shadow:3pt 3pt 3pt #D0D0D0\"></iframe>";
      }

    static String getHTML (String javascript, String bodyscript, String box)
      {
        StringBuffer s = new StringBuffer (HTML_INIT + "html, body {margin:0px;padding:0px;height:100%}</style>");
        if (javascript != null)
          {
            s.append ("<script type=\"text/javascript\">").append (javascript).append ("</script>");
          }
        s.append ("</head><body");
        if (bodyscript != null)
          {
            if (bodyscript.charAt (0) != '>')
              {
                s.append (' ');
              }
             s.append (bodyscript);
          }
        s.append ("><div onclick=\"document.location.href='")
         .append (SignatureDemoService.issuer_url)
         .append ("'\" title=\"Home sweet home...\" style=\"cursor:pointer;position:absolute;top:15px;left:15px;z-index:5;visibility:visible;padding:5pt 8pt 5pt 8pt;font-size:12pt;text-align:center;background: radial-gradient(ellipse at center, rgba(255,255,255,1) 0%,rgba(242,243,252,1) 38%,rgba(196,210,242,1) 100%);border-radius:8pt;border-width:1px;border-style:solid;border-color:#B0B0B0;box-shadow:3pt 3pt 3pt #D0D0D0;}\">" +
         "WebCrypto++<br><span style=\"font-size:8pt\">Signature Demo Home</span></div>" + "<table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\">")
         .append (box)
         .append ("</table></body></html>");
        return s.toString ();
      }
    
    static void output (HttpServletResponse response, String html) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write (html.getBytes ("UTF-8"));
      }

    public static void homePage (HttpServletResponse response) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer ("function checkWebCryptoSupport() {\n");
        s.append (
        "    if (window.crypto && window.crypto.subtle) {\n" +
        "        crypto.subtle.importKey('jwk',")
        .append (SignatureDemoService.client_private_key.getJWK ())
        .append (", {name: '")
        .append (SignatureDemoService.client_private_key.getKeyType ().equals ("EC") ? "ECDSA'" : "RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}")
        .append ("}, true, ['sign']).then (function(private_key) {\n" +
                 "            console.debug('Running in WebCrypto Mode!');\n" +
        "        }).then (undefined, function() { document.location.href = 'nowebcrypto'});\n" +
        "    } else {\n" +
        "        document.location.href = 'nowebcrypto';\n"+
        "    }\n"+
        "}\n");
        HTML.output (response, HTML.getHTML (s.toString (), "onload=\"checkWebCryptoSupport()\"",
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width:600px;\" cellpadding=\"4\">" +
                   "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">WebCrypto++ Signature Demo<br>&nbsp;</td></tr>" +
                   "<tr><td style=\"text-align:left\">This application is a demo of what a true WebCrypto++ implementation " +
                   "could offer for general purpose <span style=\"color:red\">signature systems</span>.</td></tr>" +
                   "<tr><td style=\"text-align:left\">Because WebCrypto++ <span style=\"color:red\">shields keys</span> from direct access by relying parties, " +
                   "you can effectively &quot;emulate&quot; existing signature plugins, but <span style=\"color:red\">without static installation</span>.</td></tr>" +
                   "<tr><td style=\"text-align:left\">Although the demo is <i>partially</i> a mockup (no &quot;polyfill&quot; in the world can replace WebCrypto++), " +
                   "the IFRAME solution and cross-domain communication using <code>postMessage()</code> should be pretty close to that of a real system.</td></tr>" +
                   "<tr><td align=\"center\"><table cellspacing=\"0\">" +
                   "<tr style=\"text-align:left\"><td><a href=\"" + SignatureDemoService.relying_party_url + "/signcmd\">Sign Document</a></td><td>The Demo!</td></tr>" +
                   "<tr><td style=\"text-align:center;padding-top:15pt;padding-bottom:5pt\" colspan=\"2\"><b>Documentation</b></td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/pki-webcrypto.pdf\">WebCrypto++</a></td><td><i>Conceptual</i> Specification</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://code.google.com/p/openkeystore/source/browse/#svn/wcpp-signature-demo\">Demo Source Code</a>&nbsp;&nbsp;</td><td>For Nerds...</td></tr>" +
                   "<tr><td style=\"text-align:center;padding-top:15pt;padding-bottom:5pt\" colspan=\"2\"><b>Related Applications</b></td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://mobilepki.org/jcs\">JCS</a></td><td>JSON Cleartext Signature</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://play.google.com/store/apps/details?id=org.webpki.mobile.android\">SKS/KeyGen2</a></td><td>Android PoC</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://mobilepki.org/WebCryptoPlusPlus\">Web Payments</a></td><td>WebCrypto++ Payment Demo</td></tr>" +
                 "</table></td></tr></table></td></tr>"));
      }

    static String javaScript (String string)
      {
        StringBuffer s = new StringBuffer ();
        for (char c : string.toCharArray ())
          {
            if (c == '\n')
              {
                s.append ("\\n");
              }
            else if (c == '\'')
              {
                s.append ("\\'");
              }
            else if (c == '\\')
              {
                s.append ("\\\\");
              }
            else
              {
                s.append (c);
              }
          }
        return s.toString ();
      }


    public static void noWebCryptoPage (HttpServletResponse response) throws IOException, ServletException 
      {
        HTML.output (response, HTML.getHTML (null, null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">Your Browser Doesn't Support WebCrypto :-(</td></tr>"));
      }

    public static String getBinaryArray (boolean html_flag, String date_string) throws IOException
      {
        byte[] binary = SignatureDemoService.pdf_sample;
        if (html_flag)
          {
            String temp_html = SignatureDemoService.html_template_sample.replace ("@date@", date_string.substring (0, 10));
            temp_html = temp_html.replace ("@logo@", SignatureDemoService.egov_log_uri);
            temp_html = temp_html.replace ("@prev@", "201" + (char)(date_string.charAt (3) - 1));
            binary = temp_html.getBytes ("UTF-8");
          }
        return Base64URL.encode (binary);
      }
    
    private static String niceDate (Date date)
      {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        sdf.setTimeZone (TimeZone.getTimeZone ("UTC"));
        return sdf.format (date);
      }


    private static void addCertificateProperty (String header, String data)
      {
        html_signature_frame.append ("<tr><td>").
                             append (header).
                             append ("</td><td><code>").
                             append (data).
                             append ("<code></td></tr>");
      }


    private static void addURIProperties (String header, String[] inuris) throws IOException
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
            addCertificateProperty (header, arg.toString ());
          }
      }
    
    
    private static String formatCodeString (String hex_with_spaces)
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

    private static String binaryDump (byte[] binary, boolean show_text)
      {
        return formatCodeString (DebugFormatter.getHexDebugData (binary, show_text ? 16 : -16));
      }

    private static StringBuffer html_signature_frame;
    
    public static String getHTMLSignatureFrameSource () throws IOException
      {
        html_signature_frame = new StringBuffer (
        "<!DOCTYPE html>"+
        "<html><head><meta charset=\"UTF-8\">"+
        "<style type=\"text/css\">html {overflow:hidden}\n"+
        "body {font-size:10pt;color:#000000;font-family:" + FONT_ARIAL + ";background-color:white;margin:0px;padding:0px}\n" +
        "table {border-collapse:separate; border-spacing:" + SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px}\n" +
        "td {padding: 2pt 4pt 2pt 4pt;font-size:8pt;background-color:#e0e0e8}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + ";position:absolute}\n" +
        "</style><script type=\"text/javascript\">\n" +
        "\"use strict\";\n\n" +
        "var aborted_operation = false;\n" +
        "var pin_error_count = 0;\n" +
        "var border_height;\n" +
        "var x_pos;\n" +
        "var y_pos;\n" +
        "var moving_on = false;\n" +
        "var timeouter_handle = null;\n" +
        "var request_reference_id;\n" +
        "var request_date_time;\n" +
        "var caller_common_name;\n" +
        "var caller_domain;\n" +
        "var json_request;\n" +
        "var reference_id;\n" +
        "var object_to_sign;\n" +
        "var response_date_time;\n" +
        "var mime_type;\n" +
        "var document_binary;\n" +
        "var signature_response;\n" +
        "var document_data;\n" +
        "var detached_flag;\n" +
        "var xml_flag;\n" +
        "var jws_flag;\n" +
        "var signature_object;\n" +
        "var BASE64URL_DECODE = [" +
        " -1, -1, -1, -1, -1, -1, -1, -1," +
        " -1, -1, -1, -1, -1, -1, -1, -1," +
        " -1, -1, -1, -1, -1, -1, -1, -1," +
        " -1, -1, -1, -1, -1, -1, -1, -1," +
        " -1, -1, -1, -1, -1, -1, -1, -1," +
        " -1, -1, -1, -1, -1, 62, -1, -1," +
        " 52, 53, 54, 55, 56, 57, 58, 59," +
        " 60, 61, -1, -1, -1, -1, -1, -1," +
        " -1,  0,  1,  2,  3,  4,  5,  6," +
        "  7,  8,  9, 10, 11, 12, 13, 14," +
        " 15, 16, 17, 18, 19, 20, 21, 22," +
        " 23, 24, 25, -1, -1, -1, -1, 63," +
        " -1, 26, 27, 28, 29, 30, 31, 32," +
        " 33, 34, 35, 36, 37, 38, 39, 40," +
        " 41, 42, 43, 44, 45, 46, 47, 48," +
        " 49, 50, 51];\n" +
        "var BASE64URL_ENCODE = [" + 
        "'A','B','C','D','E','F','G','H'," +
        "'I','J','K','L','M','N','O','P'," +
        "'Q','R','S','T','U','V','W','X'," +
        "'Y','Z','a','b','c','d','e','f'," +
        "'g','h','i','j','k','l','m','n'," +
        "'o','p','q','r','s','t','u','v'," +
        "'w','x','y','z','0','1','2','3'," +
        "'4','5','6','7','8','9','-','_'];\n" +
        "var BASE64STD_ENCODE = [" + 
        "'A','B','C','D','E','F','G','H'," +
        "'I','J','K','L','M','N','O','P'," +
        "'Q','R','S','T','U','V','W','X'," +
        "'Y','Z','a','b','c','d','e','f'," +
        "'g','h','i','j','k','l','m','n'," +
        "'o','p','q','r','s','t','u','v'," +
        "'w','x','y','z','0','1','2','3'," +
        "'4','5','6','7','8','9','+','/'];\n\n" +
        "//////////////////////////////////////////////////////////////////////////////\n" +
        "// This part would in a real WebCrypto++ implemenation be replaced by\n" +
        "// the platform key enumeration and attribute methods\n" +
        "var client_private_key = " + SignatureDemoService.client_private_key.getJWK () + ";\n" +
        "var client_cert_path = ['" + SignatureDemoService.client_eecert_b64 + "'];\n" +
        "var client_cert_data = " + SignatureDemoService.client_cert_data_js + ";\n" +
        "//////////////////////////////////////////////////////////////////////////////\n\n" +
        "function error(message) {\n" +
       "    console.debug ('Error: ' + message);\n" +
       "    if (!aborted_operation) {\n" +
       "        document.getElementById('content').innerHTML='<div style=\"padding:" + SIGNATURE_DIV_VERTICAL_PADDING + "px " +
       SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px " +
       SIGNATURE_DIV_HORIZONTAL_PADDING + "px\">ABORTED:<br>' + message + '</div>';\n" +
       "        aborted_operation = true;\n" +
       "    }\n" +
       "    document.getElementById('busy').style.visibility = 'hidden';\n" +
       "}\n\n" +
       "function getDomainName(url) {\n" +
       "    url = url.substring(url.indexOf('://') + 3);\n" +
       "    if (url.indexOf(':') > 0) {\n" +
       "        url = url.substring(0, url.indexOf(':'));\n" +
       "    }\n" +
       "    if (url.indexOf('/') > 0) {\n" +
       "        url = url.substring(0, url.indexOf('/'));\n" +
       "    }\n" +
       "    return url;\n" +
       "}\n\n" +
       "function checkNoErrors() {\n" +
       "   if (aborted_operation || window.self.innerWidth != " + SIGNATURE_WINDOW_WIDTH + " || window.self.innerHeight != " + SIGNATURE_WINDOW_HEIGHT + ") {\n" +
       "       error('Frame size manipulated by parent');\n" +
       "       return false;\n" +
       "   }\n" +
       "   return true;\n" +
       "}\n\n" +
       "function checkTiming(milliseconds) {\n" +
       "   timeouter_handle = setTimeout(function() {error('Timeout')}, milliseconds);\n" +
       "}\n\n" +
       "function decodeBase64URL(encoded) {\n" +
       "    var semidecoded = new Uint8Array(encoded.length);\n" +
       "    for (var i = 0; i < encoded.length; i++) {\n" +
       "        var c = encoded.charCodeAt(i);\n" +
       "        if (c >= BASE64URL_DECODE.length || (c = BASE64URL_DECODE[c]) < 0) {\n" +
       "            error('Bad character at index ' + i);\n" +
       "        }\n" +
       "        semidecoded[i] = c;\n" +
       "    }\n" +
       "    var encoded_length_modulo_4 = Math.floor(encoded.length % 4);\n" +
       "    var decoded_length = Math.floor(encoded.length / 4) * 3;\n" +
       "    if (encoded_length_modulo_4 != 0) {\n" +
       "        decoded_length += encoded_length_modulo_4 - 1;\n" +
       "    }\n" +
       "    var decoded = new Uint8Array(decoded_length);\n" +
       "    var decoded_length_modulo_3 = Math.floor(decoded_length % 3);\n" +
       "    if (decoded_length_modulo_3 == 0 && encoded_length_modulo_4 != 0) {\n" +
       "        error('Wrong number of characters');\n" +
       "    }\n" +
       "    var i = 0, j = 0;\n" +
       "    while (j < decoded.length - decoded_length_modulo_3) {\n" +
       "        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);\n" +
       "        decoded[j++] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);\n" +
       "        decoded[j++] = (semidecoded[i++] << 6) | semidecoded[i++];\n" +
       "    }\n" +
       "    if (decoded_length_modulo_3 == 1) {\n" +
       "        decoded[j] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);\n" +
       "        if (semidecoded[i] & 0x0F) {\n" +
       "            error('Wrong termination character');\n" +
       "        }\n" +
       "    }\n" +
       "    else if (decoded_length_modulo_3 == 2) {\n" +
        "        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);\n" +
       "        decoded[j] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);\n" +
       "        if (semidecoded[i] & 0x03) {\n" +
       "            error('Wrong termination character');\n" +
       "        }\n" +
       "    }\n" +
       "    return decoded;\n" +
       "}\n\n" +
       "function _bin2b64(binarray, b64table) {\n" +
        "    var encoded = new String ();\n" +
        "    var i = 0;\n" +
        "    var modulo3 = binarray.length % 3;\n" +
        "    while (i < binarray.length - modulo3) {\n" +
        "        encoded += b64table[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += b64table[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" +
        "        encoded += b64table[((binarray[i++] << 2) & 0x3C) | ((binarray[i] >>> 6) & 0x03)];\n" +
        "        encoded += b64table[binarray[i++] & 0x3F];\n" +
        "    }\n" +
        "    if (modulo3 == 1) {\n" +
        "        encoded += b64table[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += b64table[(binarray[i] << 4) & 0x30];\n" +
        "    }\n" +
        "    else if (modulo3 == 2) {\n" +
        "        encoded += b64table[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += b64table[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" +
        "        encoded += b64table[(binarray[i] << 2) & 0x3C];\n" +
        "    }\n" +
        "    return encoded;\n" +
        "}\n\n" +
        "function binaryToBase64URL(binarray) {\n" +
        "    return _bin2b64(binarray, BASE64URL_ENCODE);\n" +
        "}\n\n" +
        "function binaryToBase64STD(binarray) {\n" +
        "    var b64 = _bin2b64(binarray, BASE64STD_ENCODE);\n" +
        "    while (b64.length % 4) {\n" +
        "        b64 += '=';\n" +
        "    }\n" +
        "    return b64;\n" +
        "}\n\n" +
        "function convertStringToUTF8(string) {\n" +
        "    var buffer = [];\n" +
        "    for (var n = 0; n < string.length; n++) {\n" +
        "        var c = string.charCodeAt(n);\n" +
        "        if (c < 128) {\n" +
        "            buffer.push (c);\n" +
        "        } else if ((c > 127) && (c < 2048)) {\n" +
        "            buffer.push((c >> 6) | 0xC0);\n" +
        "            buffer.push((c & 0x3F) | 0x80);\n" +
        "        } else {\n" +
        "            buffer.push((c >> 12) | 0xE0);\n" +
        "            buffer.push(((c >> 6) & 0x3F) | 0x80);\n" +
        "            buffer.push((c & 0x3F) | 0x80);\n" +
        "        }\n" +
        "    }\n" +
        "    return new Uint8Array(buffer);\n" +
        "}\n\n" +
        "function convertUTF8ToString(utf8data) {\n" +
        "    var encoded_string = String.fromCharCode.apply(null, utf8data);\n" +
        "    return decodeURIComponent(escape(encoded_string));\n" +
        "}\n\n" +
        "function createJSONBaseCommand(command_property_value) {\n" +
        "    var json = {};\n" +
        "    json['" + JSONDecoderCache.CONTEXT_JSON + "'] = '" + WCPP_DEMO_CONTEXT_URI + "';\n" +
        "    json['" + JSONDecoderCache.QUALIFIER_JSON + "'] = command_property_value;\n" +
        "    return json;\n" +
        "}\n\n" +
        "function getJSONProperty(property) {\n" +
        "    var value = json_request[property];\n" +
        "    if (value === undefined) {\n" +
        "        error('Missing property: ' + property);\n" +
        "        return null;\n" +
        "    }\n" +
        "    return value;\n" +
        "}\n\n" +
        "function userAbort() {\n" +
        "    window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" + 
             Messages.ABORT +
             "')), window.document.referrer);\n" +
        "}\n\n" +
        "function mouseDown(ev) {\n" +
        "    x_pos = ev.clientX;\n" +
        "    y_pos = ev.clientY;\n" +
        "    moving_on = true;\n" +
        "}\n\n" +
        "function mouseUp(ev) {\n" +
        "    moving_on = false;\n" +
        "}\n\n" +
        "function mouseLeave(ev) {\n" +
        "    moving_on = false;\n" +
        "}\n\n" +
        "function mouseMove(ev) {\n" +
        "    var x = ev.clientX;\n" +
        "    var y = ev.clientY;\n" +
        "    var elem = document.getElementById(ev.target.id == 'pinborder' ? 'pindialog' : 'credential');\n" +
        "    if (moving_on) {\n" +
        "        elem.style.top = (parseInt(elem.style.top.replace('px','')) + y - y_pos) + 'px';\n" +
        "        elem.style.left = (parseInt(elem.style.left.replace('px','')) + x - x_pos) + 'px';\n" +
        "    }\n" +
        "    y_pos = y;\n" +
        "    x_pos = x;\n" +
        "}\n" +
        "function addDragHandlers(id) {\n" +
        "   var elem = document.getElementById(id);\n" +
        "   elem.addEventListener('mousedown', mouseDown);\n" +
        "   elem.addEventListener('mouseup', mouseUp);\n" +
        "   elem.addEventListener('mousemove', mouseMove);\n" +
        "   elem.addEventListener('mouseleave', mouseLeave);\n" +
        "}\n\n" +
        "function removeDragHandlers(id) {\n" +
        "   moving_on = false;\n" +
        "   var elem = document.getElementById(id);\n" +
        "   elem.removeEventListener('mousedown', mouseDown);\n" +
        "   elem.removeEventListener('mouseup', mouseUp);\n" +
        "   elem.removeEventListener('mousemove', mouseMove);\n" +
        "   elem.removeEventListener('mouseleave', mouseLeave);\n" +
        "}\n\n" +
        "function openCredentialDialog() {\n" +
        "    closePINDialog();\n" +
        "    addDragHandlers('credborder');\n" +
        "    document.getElementById('credential').style.visibility = 'visible';\n" +
        "}\n\n" +
        "function closeCredentialDialog() {\n" +
        "    removeDragHandlers('credborder');\n" +
        "    document.getElementById('credential').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function userSign() {\n" +
        "    closeCredentialDialog();\n" +
        "    document.getElementById('sign').disabled = true;\n" +
        "    var pindialog_width = document.getElementById('pindialog').offsetWidth;\n" +
        "    document.getElementById('pincross').style.height = (border_height - 9) + 'px';\n" +
        "    document.getElementById('pincross').style.top = '4px';\n" +
        "    document.getElementById('pincross').style.left = (pindialog_width - border_height + 2) + 'px';\n" +
        "    document.getElementById('pindialog').style.top = Math.floor((" + SIGNATURE_WINDOW_HEIGHT + " - document.getElementById('pindialog').offsetHeight) / 2) + 'px';\n" +
        "    document.getElementById('pindialog').style.left = Math.floor((" + SIGNATURE_WINDOW_WIDTH + " - pindialog_width) / 2) + 'px';\n" +
        "    addDragHandlers('pinborder');\n" +
        "    document.getElementById('pindialog').style.visibility = 'visible';\n" +
        "    document.getElementById('pin').focus();\n" +
        "}\n\n" +
        "function closePINDialog() {\n" +
        "    removeDragHandlers('pinborder');\n" +
        "    document.getElementById('sign').disabled = false;\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function showPINError(message) {\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "    document.getElementById('pinerror').innerHTML = '<div style=\"padding:8pt 12pt 0pt 12pt;color:red\">' + message + '</div>';\n" +
        "    userSign();\n" +
        "}\n\n" +
        "function beautifyXMLDSig(element) {\n" +
        "    signature_response = signature_response.replace(new RegExp('\\>\\<\\/' + element + '\\>', 'g'), '/>');\n" +
        "}\n\n" +
        "function createXMLReference(id, extra, data, f) {\n" +
        "    crypto.subtle.digest({name: 'SHA-256'}, convertStringToUTF8(data)).then (function(result) {\n" +
        "        f('<ds:Reference URI=\"' + id + '\"><ds:Transforms>' + extra" +
        " + '<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>" +
        "</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
        "<ds:DigestValue>' + binaryToBase64STD(new Uint8Array(result)) + '</ds:DigestValue></ds:Reference>');\n" +
        "    }).then (undefined, function() {error('Failed hashing document')});\n" +
        "}\n\n" +
        "function addXMLAttribute(name, value) {\n" +
        "    signature_response += ' ' + name + '=\"' + value + '\"';\n" +
        "}\n\n" +
        "function signXMLAndSend() {\n" +
        "    signature_response += '></" + DOCUMENT_DATA_JSON + ">';\n" +
        "    var start_tag = '<" + Messages.SIGNATURE_RESPONSE.toString () + " ';\n" +
        "    var end_tag = '</" + Messages.SIGNATURE_RESPONSE.toString () + ">';\n" +
        "    // GENERATING canonicalized XML is usually quite simple, it is the RECREATING that's difficult\n" +
        "    var key_info = '<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"sig.key\"><ds:X509Data><ds:X509IssuerSerial><ds:X509IssuerName>'" +
                 " + client_cert_data." + JSONSignatureDecoder.ISSUER_JSON + 
                 " + '</ds:X509IssuerName><ds:X509SerialNumber>'" + 
                 " + client_cert_data." + JSONSignatureDecoder.SERIAL_NUMBER_JSON +
                 " + '</ds:X509SerialNumber></ds:X509IssuerSerial><ds:X509SubjectName>'" +
                 " + client_cert_data." + JSONSignatureDecoder.SUBJECT_JSON +
                 " + '</ds:X509SubjectName>';\n" +
        "     for (var i = 0; i < client_cert_path.length; i++) {\n" +
        "         key_info += '<ds:X509Certificate>'+ binaryToBase64STD(decodeBase64URL(client_cert_path[i]))" +
                 " + '</ds:X509Certificate>';\n" +
        "     }\n" +
        "     key_info += '</ds:X509Data></ds:KeyInfo>';\n" +
             "    createXMLReference(''," +
             "'<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\">" +
             "</ds:Transform>', start_tag + signature_response + end_tag, function(doc_ref) {\n" +
        "    createXMLReference('#sig.key','', key_info, function(key_ref) {\n" +
        "        var signed_info = '<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod Algorithm=\"" +
             "http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"" +
             "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>' + doc_ref + key_ref + '</ds:SignedInfo>';\n" +
        "        var key_import_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "        var key_signature_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "        crypto.subtle.importKey('jwk', client_private_key, key_import_alg, false, ['sign']).then (function(private_key) {\n" +
        "        crypto.subtle.sign (key_signature_alg, private_key, convertStringToUTF8(signed_info)).then (function(signature) {\n" +
        "            signature_response += '<ds:Signature>' + signed_info + '<ds:SignatureValue>'" +
                     " + binaryToBase64STD(new Uint8Array(signature)) + '</ds:SignatureValue>' + key_info" +
                     " + '</ds:Signature>';\n" +
        "            // XML canonicalization requires a lot of ugly \"junk\" which the the following lines remove\n" +
        "            // The verifier will have to put it back but that's the verifier's problem :-)\n" +
        "            signature_response = signature_response.replace(/\\ xmlns\\:ds\\=\\\"http:\\/\\/www\\.w3\\.org\\/2000\\/09\\/xmldsig#\\\"/g,'');\n" +
        "            beautifyXMLDSig('ds:CanonicalizationMethod');\n" +
        "            beautifyXMLDSig('ds:Transform');\n" +
        "            beautifyXMLDSig('ds:SignatureMethod');\n" +
        "            beautifyXMLDSig('ds:DigestMethod');\n" +
        "            beautifyXMLDSig('" + REQUEST_DATA_JSON + "');\n" +
        "            beautifyXMLDSig('" + DOCUMENT_HASH_JSON + "');\n" +
        "            // End of the XML \"beautifying\" process\n" +
        "            window.parent.postMessage('<?xml version=\"1.0\" encoding=\"UTF-8\"?>'" +
                     " + start_tag + 'xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" '" + 
                     " + signature_response + end_tag, window.document.referrer);\n" +
        "        }).then (undefined, function() {error('Failed signing')});\n" +
        "        }).then (undefined, function() {error('Failed importing private key')});\n" +
        "    });\n" +
        "    });\n" +
        "}\n\n" +
        "function createXMLSignature() {\n" +
        "    signature_response = 'xmlns=\"" + WCPP_DEMO_CONTEXT_URI + "\"';\n" +
        "    addXMLAttribute ('" + DATE_TIME_JSON + "', response_date_time);\n" +
        "    signature_response += '><" + REQUEST_DATA_JSON + "';\n" +
        "    addXMLAttribute ('" + DATE_TIME_JSON + "', request_date_time);\n" +
        "    addXMLAttribute ('" + ORIGIN_JSON + "', window.document.referrer);\n" +
        "    addXMLAttribute ('" + REFERENCE_ID_JSON + "', reference_id);\n" +
        "    signature_response += '></" + REQUEST_DATA_JSON + "><" + DOCUMENT_DATA_JSON + "';\n" +
        "    addXMLAttribute ('" + MIME_TYPE_JSON + "', mime_type);\n" +
        "    if (detached_flag) {\n" +
        "        signature_response += '><" + DOCUMENT_HASH_JSON + "';\n" +
        "        addXMLAttribute ('" + ALGORITHM_JSON + "', '" + HashAlgorithms.SHA256.getURI () + "');\n" +
        "        crypto.subtle.digest({name: 'SHA-256'}, document_binary).then (function(result) {\n" +
        "            addXMLAttribute ('" + VALUE_JSON + "', binaryToBase64STD(new Uint8Array(result)));\n" +
        "            signature_response += '></" + DOCUMENT_HASH_JSON + "';\n" +
        "            signXMLAndSend();\n" +
        "        }).then (undefined, function() {error('Failed hashing document')});\n" +
        "    } else {\n" +
        "        signature_response += '><" + DOCUMENT_JSON + ">' + binaryToBase64STD(document_binary)" +
                 " + '</" + DOCUMENT_JSON + "';\n" +
        "        signXMLAndSend();\n" +
        "    }\n" +
        "}\n\n" +
        "function createJWSSignature(key_import_alg, key_signature_alg) {\n" +
        "    var header = {}\n" +
        "    header.alg = 'RS256';\n" +
        "    header.x5c = []\n" +
        "    for (var i = 0; i < client_cert_path.length; i++) {\n" +
        "        header.x5c.push(binaryToBase64STD(decodeBase64URL(client_cert_path[i])));\n" +
        "    }\n" +
        "    var data2sign = binaryToBase64URL(convertStringToUTF8(JSON.stringify(header))) + '.'" +
             " + binaryToBase64URL(convertStringToUTF8(JSON.stringify(signature_response)));\n" +
        "    crypto.subtle.importKey('jwk', client_private_key, key_import_alg, false, ['sign']).then (function(private_key) {\n" +
        "    crypto.subtle.sign (key_signature_alg, private_key, convertStringToUTF8(data2sign)).then (function(signature) {\n" +
         "        window.parent.postMessage(data2sign + '.' + binaryToBase64URL(new Uint8Array(signature)), window.document.referrer);\n" +
        "    }).then (undefined, function() {error('Failed signing')});\n" +
        "    }).then (undefined, function() {error('Failed importing private key')});\n" +
        "}\n\n" +
        "function createSignatureAndSend(key_import_alg, key_signature_alg, jcs_alg) {\n" +
        "    if (jws_flag) {\n" +
        "        createJWSSignature(key_import_alg, key_signature_alg);\n" +
        "        return;\n" +
        "    }\n" +
        "    signature_object = signature_response." + JSONSignatureDecoder.SIGNATURE_JSON + " = {};\n" +
        "    signature_object." + JSONSignatureDecoder.ALGORITHM_JSON + " = jcs_alg;\n" +
        "    var key_info = signature_object." + JSONSignatureDecoder.KEY_INFO_JSON + " = {};\n"+
        "    key_info." + JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON + " = client_cert_data;\n" +
        "    key_info." + JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON + " = client_cert_path;\n" +
        "    crypto.subtle.importKey('jwk', client_private_key, key_import_alg, false, ['sign']).then (function(private_key) {\n" +
        "    crypto.subtle.sign (key_signature_alg, private_key, convertStringToUTF8(JSON.stringify(signature_response))).then (function(signature) {\n" +
        "        signature_object." + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + " = binaryToBase64URL(new Uint8Array(signature));\n" +
        "        window.parent.postMessage(JSON.stringify(signature_response), window.document.referrer);\n" +
        "    }).then (undefined, function() {error('Failed signing')});\n" +
        "    }).then (undefined, function() {error('Failed importing private key')});\n" +
        "}\n\n" +
        "function performSignatureOperation() {\n" +
        "    var pin = document.getElementById('pin').value;\n" +
        "    if (pin_error_count < 3) {\n" +
        "        if (pin.length == 0) {\n" +
        "            showPINError('Please enter a PIN...');\n" +
        "            return;\n" +
        "        }\n" +
        "        if (pin != '1234') {\n" +
        "            if (++pin_error_count < 3) {\n" +
        "                showPINError('Incorrect PIN! Attempts left: ' + (3 - pin_error_count));\n" +
        "                return;\n" +
        "            }\n" +
        "        }\n" +
        "    }\n" +
        "    if (pin_error_count == 3) {\n" +
        "        showPINError('Too many PIN errors,<br>the key is blocked!');\n" +
        "        return;\n" +
        "    }\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "    document.getElementById('busy').style.visibility = 'visible';\n" +
        "    response_date_time = new Date().toISOString();\n" +
        "    if (response_date_time.indexOf('.') > 0 && response_date_time.indexOf('Z') > 0) {\n" +
        "        response_date_time = response_date_time.substring (0, response_date_time.indexOf('.')) + 'Z';\n" +
        "    }\n" +
        "    if (xml_flag) {\n" +
        "        createXMLSignature();\n" +
        "        return;\n" +
        "    }\n" +
        "    signature_response = createJSONBaseCommand('" + Messages.SIGNATURE_RESPONSE + "');\n" +
        "    var request_data = signature_response." + REQUEST_DATA_JSON + " = {};\n" +
        "    request_data." + ORIGIN_JSON + " = window.document.referrer;\n" +
        "    request_data." + REFERENCE_ID_JSON + " = reference_id;\n" +
        "    request_data." + DATE_TIME_JSON + " = request_date_time;\n" +
        "    document_data = signature_response." + DOCUMENT_DATA_JSON + " = {};\n" +
        "    signature_response." + DATE_TIME_JSON + " = response_date_time;\n" +
        "    document_data." + MIME_TYPE_JSON + " = mime_type;\n" +
        "    var key_import_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "    var key_signature_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "    var jcs_alg = '" + AsymSignatureAlgorithms.RSA_SHA256.getURI () + "';\n" +
        "    if (client_private_key.kty == 'EC') {\n" +
        "        error('Not implemented yet');\n" +
        "    }\n" +
        "    if (detached_flag) {\n" +
        "        var document_hash = document_data." + DOCUMENT_HASH_JSON + " = {};\n" +
        "        document_hash." + JSONSignatureDecoder.ALGORITHM_JSON + " = '" + HashAlgorithms.SHA256.getURI () + "';\n" +
        "        crypto.subtle.digest({name: 'SHA-256'}, document_binary).then (function(result) {\n" +
        "            document_hash." + VALUE_JSON + " = binaryToBase64URL(new Uint8Array(result));\n" +
        "            createSignatureAndSend(key_import_alg, key_signature_alg, jcs_alg);\n" +
        "        }).then (undefined, function() {error('Failed hashing document')});\n" +
        "    } else {\n" +
        "        document_data." + DOCUMENT_JSON + " = object_to_sign." + DOCUMENT_JSON + ";\n" +
        "        createSignatureAndSend(key_import_alg, key_signature_alg, jcs_alg);\n" +
        "    }\n" +
        "}\n\n" +
        "function processInvoke() {\n" +
        "    object_to_sign = getJSONProperty('" + OBJECT_TO_SIGN_JSON + "');\n" +
        "    if (aborted_operation) return;\n" +
        "    mime_type = object_to_sign." + MIME_TYPE_JSON + ";\n" +
        "    document_binary = decodeBase64URL(object_to_sign." + DOCUMENT_JSON + ");\n" +
        "    reference_id = getJSONProperty('" + REFERENCE_ID_JSON + "');\n" +
        "    request_date_time = getJSONProperty('" + DATE_TIME_JSON + "');\n" +
        "    detached_flag = getJSONProperty('" + SIGNATURE_TYPE_JSON + "') == '" + SIGNATURE_TYPE_DETACHED + "';\n" +
        "    xml_flag = getJSONProperty('" + SIGNATURE_FORMAT_JSON + "') == '" + SIGNATURE_FORMAT_XML_DSIG + "';\n" +
        "    jws_flag = getJSONProperty('" + SIGNATURE_FORMAT_JSON + "') == '" + SIGNATURE_FORMAT_JWS + "';\n" +
        "    if (aborted_operation) return;\n" +
        "    border_height = document.getElementById('border').offsetHeight;\n" +
        "    var credential_width = document.getElementById('credential').offsetWidth;\n" +
        "    document.getElementById('credcross').style.height = (border_height - 9"
        + ") + 'px';\n" +
        "    document.getElementById('credcross').style.top = '4px';\n" +
        "    document.getElementById('credcross').style.left = (credential_width - border_height + 2) + 'px';\n" +
        "    var button_height = document.getElementById('cancel').offsetHeight;\n" +
        "    var attention_height = document.getElementById('attention').offsetHeight;\n" +
        "    var diff = attention_height - 2 * button_height;\n" +
        "    var control_height = (diff < 0 ? attention_height + diff : attention_height) + Math.floor(button_height / 3);\n" +
        "    if ((attention_height & 1) != (control_height & 1)) {\n" +
        "        control_height++;\n" +
        "    }\n" +
        "    document.getElementById('control').style.height = control_height + 'px';\n" +
        "    var button_width = document.getElementById('sign').offsetWidth;\n" +
        "    var button_h_margin = Math.floor(button_width / 4);\n" +
        "    document.getElementById('cancel').style.left = button_h_margin + 'px';\n" +
        "    document.getElementById('cancel').style.width = button_width + 'px';\n" +
        "    document.getElementById('cancel').style.top = document.getElementById('sign').style.top = (Math.floor((control_height - button_height) / 2)) + 'px';\n" +
        "    var attention_left = " + SIGNATURE_WINDOW_WIDTH + " - 2 * button_h_margin - button_width - document.getElementById('attention').offsetWidth;\n" +
        "    document.getElementById('attention').style.left = attention_left + 'px';\n" +
        "    document.getElementById('attention').style.top = Math.floor((control_height - attention_height) / 2) + 'px';\n" +
        "    document.getElementById('sign').style.left = (" + SIGNATURE_WINDOW_WIDTH + " - button_h_margin - button_width) + 'px';\n" +
        "    document.getElementById('keylogo').style.height = (attention_height - 2) + 'px';\n" +
        "    var keylogo_width = Math.floor((attention_height - 2) * 1.5);\n" +
        "    document.getElementById('keylogo').style.width = keylogo_width + 'px';\n" +
        "    document.getElementById('keylogo').style.top = document.getElementById('attention').style.top;\n" +
        "    var username_width = document.getElementById('username').offsetWidth;\n" +
        "    var keylogo_left = Math.floor((attention_left - keylogo_width - username_width + button_width + button_h_margin) / 2);\n" +
        "    document.getElementById('keylogo').style.left = keylogo_left + 'px';\n" +
        "    document.getElementById('username').style.left = (keylogo_left + keylogo_width) + 'px';\n" +
        "    document.getElementById('username').style.top = Math.floor((control_height - document.getElementById('username').offsetHeight) / 2) + 'px';\n" +
        "    document.getElementById('credential').style.top = Math.floor((" + SIGNATURE_WINDOW_HEIGHT + " - document.getElementById('credential').offsetHeight) / 2) + 'px';\n" +
        "    document.getElementById('credential').style.left = Math.floor((" + SIGNATURE_WINDOW_WIDTH + " - credential_width) / 2) + 'px';\n" +
        "    document.getElementById('control').style.visibility = 'visible';\n" +
        "    console.debug('Doclen=' + document_binary.length);\n" +
        "    var frame_height = " + SIGNATURE_WINDOW_HEIGHT + 
             " - border_height - control_height;\n" +
        "    document.getElementById('content').innerHTML = '<iframe src=\"data:' + mime_type + ';base64,' + binaryToBase64STD(document_binary)" +
               " + '\" style=\"width:" + SIGNATURE_WINDOW_WIDTH + 
               "px;height:' + frame_height + 'px;border-width:0px\"></iframe>';\n" +
        "}\n\n" +
        "window.addEventListener('message', function(event) {\n" +
        "    console.debug(event.origin + ' => SignatureFrame:\\n' + event.data);\n" +
        "    if (aborted_operation) return;\n" +
        "    if (timeouter_handle) {\n" +
        "        clearTimeout(timeouter_handle);\n" +
        "        timeouter_handle = null;\n" +
        "        json_request = JSON.parse(event.data);\n" +
        "        if (getJSONProperty('" + JSONDecoderCache.CONTEXT_JSON + "') == '" + WCPP_DEMO_CONTEXT_URI + "' && " +
                 "getJSONProperty('" + JSONDecoderCache.QUALIFIER_JSON + "') == '" + Messages.SIGNATURE_REQUEST + "') {\n" +
        "            processInvoke();\n" +
        "            document.getElementById('busy').style.visibility = 'hidden';\n" +
        "            return;\n" +
        "        }\n" +
        "    }\n" +
        "    error('Unexpected message: ' + event.origin + ' ' + event.data);\n" +
        "}, false);\n\n" +
        "function initSignatureApplication() {\n" +
        "    caller_domain = getDomainName(window.document.referrer);\n" +
        "    document.getElementById('border').innerHTML += ' [' + caller_domain + ']';\n" +
        "    if (checkNoErrors()) {\n" +
        "        console.debug('Init Signature Application');\n" +
        "        checkTiming(" + SIGNATURE_TIMEOUT_INIT + ");\n" +
        "        window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" + 
                 Messages.INIIALIZE +
                 "')), window.document.referrer);\n" +
        "    }\n" +
        "}\n" +
        "</script></head><body onload=\"initSignatureApplication()\">" +
        "<div id=\"border\" style=\"font-family:" + FONT_VERDANA + ";padding:" + (SIGNATURE_DIV_VERTICAL_PADDING - 1) + "px " +
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px " +
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px;" +
        "color:white;background:" +
        SIGNATURE_BORDER_COLOR + ";width:" +
        (SIGNATURE_WINDOW_WIDTH - (SIGNATURE_DIV_HORIZONTAL_PADDING * 2)) +"px\">Signature Request</div>" +
        "<div id=\"content\" style=\"overflow-y:auto\">" +
        "<div style=\"padding:" + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px\">Initializing...</div></div>" +
        "<div id=\"control\" style=\"background:" + SIGNATURE_DIALOG_COLOR + ";border-width:1px 0px 0px 0px;border-style:solid;border-color:" + 
        SIGNATURE_BORDER_COLOR + ";z-index:3;position:absolute;bottom:0px;width:" + SIGNATURE_WINDOW_WIDTH +"px;visibility:hidden\">" +
          "<input id=\"cancel\" title=\"Return to previous view\"  type=\"button\" value=\"&nbsp;Cancel&nbsp;\" class=\"stdbtn\" onclick=\"userAbort()\">" +
          "<input id=\"sign\" title=\"Continue to the final - The PIN dialog\" type=\"button\" value=\"Continue...\" class=\"stdbtn\"onclick=\"userSign()\">" +
          "<div id=\"attention\" style=\"padding:2px 4px 2px 4px;font-size:8pt;position:absolute;border-radius:4pt;border-width:1px;border-style:solid;border-color:red;background-color:#FFFFE0\">By digitally signing the document above,<br>you confirm that you have read and<br>understood the implications of its content</div>" +
          "<img id=\"keylogo\" title=\"Signature credential - Click for more information\" onclick=\"openCredentialDialog()\" src=\"" + 
             SignatureDemoService.mybank_data_uri + 
             "\" alt=\"html5 requirement...\" style=\"cursor:pointer;border-radius:4pt;background:white;position:absolute;border-width:1px;border-style:solid;border-color:black\">" + 
          "<div id=\"username\" title=\"User &quot;Common Name&quot;\" style=\"position:absolute;padding:6pt\">" + SignatureDemoService.user_name + "</div>" +
        "</div>" +
        "<img id=\"busy\" src=\"" + SignatureDemoService.working_data_uri + "\" alt=\"html5 requirement...\" style=\"position:absolute;top:" + 
        ((SIGNATURE_WINDOW_HEIGHT - SIGNATURE_LOADING_SIZE) / 2) + "px;left:" + 
        ((SIGNATURE_WINDOW_WIDTH - SIGNATURE_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        getDialogBox ("pindialog",
                      "pinborder",
                      "pincross",
                      "Enter a PIN to activate the signature key...", 
                      "Signature PIN",
                      "closePINDialog") +
        "<div id=\"pinerror\"></div>" +
        "<div style=\"text-align:center;padding:12pt 15pt 8pt 15pt\"><input id=\"pin\" " +
             "title=\"Try &quot;1234&quot; :-)\" style=\"font-family:" + FONT_VERDANA + ";padding-left:3px;letter-spacing:2px;background-color:white\" " +
             "type=\"password\" size=\"" + PIN_FIELD_SIZE +
             "\" maxlength=\"" + PIN_MAX_LENGTH + "\"></div>" +
         "<div style=\"text-align:center;padding:0pt 15pt 12pt 15pt\"><input style=\"font-weight:normal;font-size:10pt;font-family:" + 
             FONT_ARIAL + "\" type=\"button\"  title=\"This button activates the signature key\" value=\"Sign Document\" onclick=\"performSignatureOperation()\"></div>" +
        "</div>" +
        getDialogBox ("credential",
                      "credborder",
                      "credcross",
                      "Currently a &quot;selection&quot; of properties...", 
                      "Certificate Properties",
                      "closeCredentialDialog") +
          "<div style=\"background-color:white;overflow:scroll;max-width:500px;max-height:400px\"><table>");
            CertificateInfo cert_info = new CertificateInfo (SignatureDemoService.client_eecert);
            addCertificateProperty ("Issuer", HTMLEncoder.encode (cert_info.getIssuer ()));
            addCertificateProperty ("Serial&nbsp;number", cert_info.getSerialNumber () + " (0x" + cert_info.getSerialNumberInHex () + ")");
            addCertificateProperty ("Subject", HTMLEncoder.encode (cert_info.getSubject ()));
            addCertificateProperty ("Valid&nbsp;from", niceDate (cert_info.getNotBeforeDate ()));
            addCertificateProperty ("Valid&nbsp;to", niceDate (cert_info.getNotAfterDate ()));
            String bc = cert_info.getBasicConstraints ();
            if (bc != null)
              {
                addCertificateProperty ("Basic&nbsp;constraints", bc);
              }
            addURIProperties ("Key&nbsp;usage", cert_info.getKeyUsages ());
            String[] ext_key_usages = cert_info.getExtendedKeyUsage ();
            if (ext_key_usages != null)
              {
                for (int i = 0; i < ext_key_usages.length; i++)
                  {
                    ext_key_usages[i] = ExtendedKeyUsages.getOptionallyTranslatedEKU (ext_key_usages[i]);
                  }
                addURIProperties ("Extended&nbsp;key&nbsp;usage", ext_key_usages);
              }
            addURIProperties ("Policy&nbsp;OIDs", cert_info.getPolicyOIDs ());
            addURIProperties ("AIA&nbsp;CA&nbsp;issuers", cert_info.getAIACAIssuers ());
            addURIProperties ("OCSP&nbsp;reponders", cert_info.getAIAOCSPResponders ());
            String fp = ArrayUtil.toHexString (cert_info.getCertificateHash (), 0, -1, true, ' ');
            addCertificateProperty ("SHA1&nbsp;fingerprint", fp.substring (0, 29) + "<br>" + fp.substring (29));
            addCertificateProperty ("Key&nbsp;algorithm", cert_info.getPublicKeyAlgorithm ());
            addCertificateProperty ("Public&nbsp;key", binaryDump (cert_info.getPublicKeyData (), false));
            html_signature_frame.append ("</table></div></div>");

        return html_signature_frame.append ("</body></html>").toString ();
      }

    private static String getDialogBox (String main_id,
                                        String border_id,
                                        String cross_id,
                                        String title_text,
                                        String header_text,
                                        String close_method)
      {
        return 
          "<div id=\"" + main_id + "\" title=\"" + title_text + "\" " +
            "style=\"background-color:" + SIGNATURE_DIALOG_COLOR + ";border-width:1px;border-style:solid;border-color:" +
                 SIGNATURE_BORDER_COLOR + 
                 ";box-shadow:3pt 3pt 3pt #D0D0D0;position:absolute;visibility:hidden;z-index:3\">" +
            "<div id=\"" + border_id + "\" style=\"cursor:move;font-family:" + FONT_VERDANA + ";padding:" + (SIGNATURE_DIV_VERTICAL_PADDING - 1) + "px " + 
            30 + "pt " + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
            SIGNATURE_DIV_HORIZONTAL_PADDING + "px;" +
            "color:white;background:" +
            SIGNATURE_BORDER_COLOR + "\">" + header_text + "<img src=\"" + SignatureDemoService.cross_data_uri + 
            "\" id=\"" + cross_id + "\" onclick=\"" + close_method + "()\" " +
            "title=\"Click to close\" style=\"cursor:pointer;position:absolute\"></div>";
      }

    public static void signData (HttpServletResponse response, boolean html_flag, boolean json_flag, boolean jws_flag, boolean detached_flag) throws IOException, ServletException 
      {
        String date_string = ISODateTime.formatDateTime (new Date (), true);
        String reference_id = "#" +  SignatureDemoService.reference_id++;
        String mime_type = html_flag ? "text/html" : "application/pdf";
        HTML.output (response, HTML.getHTML (
        "\n\n\"use strict\";\n\n" +
        "var message_state = '" + Messages.INIIALIZE + "';\n\n" +
        "function createJSONBaseCommand(command_property_value) {\n" +
        "    var json = {};\n" +
        "    json['" + JSONDecoderCache.CONTEXT_JSON + "'] = '" + WCPP_DEMO_CONTEXT_URI + "';\n" +
        "    json['" + JSONDecoderCache.QUALIFIER_JSON + "'] = command_property_value;\n" +
        "    return json;\n" +
        "}\n\n" +
        "window.addEventListener('message', function(event) {\n" +
        "    console.debug (event.origin + ' = > Signature message:\\n' + event.data);\n" +
        (json_flag ? (jws_flag ? 
            "    if (message_state == '" + Messages.SIGNATURE_RESPONSE + "' && event.data.charAt(0) != '{') {\n" +
            "        document.getElementById('signature').value = event.data;\n" +
            "        setTimeout(function(){\n" +
            "            document.forms.shoot.submit();\n" +
            "        }, 0);\n" +
            "        return;\n" +
            "    }\n"
            :
            "")
            :
        "    if (message_state == '" + Messages.SIGNATURE_RESPONSE + "' && event.data.charAt(0) == '<') {\n" +
        "        document.getElementById('signature').value = event.data;\n" +
        "        setTimeout(function(){\n" +
        "            document.forms.shoot.submit();\n" +
        "        }, 0);\n" +
        "        return;\n" +
        "    }\n") +
        "    var received_json = JSON.parse(event.data);\n" +
        "    if (received_json['" + JSONDecoderCache.CONTEXT_JSON + "'] != '" + WCPP_DEMO_CONTEXT_URI + "') {\n" +
        "        console.debug('UNDECODABLE MESSAGE');\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] == '" + Messages.ABORT + "') {\n" +
        "        document.location.href='" + SignatureDemoService.issuer_url + "/signcmd';\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] != message_state) {\n" +
        "        console.debug('STATE ERROR: ' + event.data + '/' + message_state);\n" +
        "        return;\n" +
        "    }\n" +
        "    if (message_state == '" + Messages.INIIALIZE + "') {\n" +
        "        var invoke_object = createJSONBaseCommand('" + Messages.SIGNATURE_REQUEST + "');\n" +
        "        invoke_object." + REFERENCE_ID_JSON + " = '" +  reference_id + "';\n" +
        "        invoke_object." + DATE_TIME_JSON + " = '" + date_string + "';\n" +
        "        invoke_object." + SIGNATURE_FORMAT_JSON + " = '" + (json_flag ? (jws_flag ? SIGNATURE_FORMAT_JWS : SIGNATURE_FORMAT_JCS) : SIGNATURE_FORMAT_XML_DSIG) + "';\n" +
        "        invoke_object." + SIGNATURE_TYPE_JSON + " = '" + (detached_flag ? SIGNATURE_TYPE_DETACHED : SIGNATURE_TYPE_EMBEDDING) + "';\n" +
        "        invoke_object." + SIGNATURE_ALGORITHMS_JSON + " = ['" + 
                     AsymSignatureAlgorithms.ECDSA_SHA256.getURI () + "','" +
                     AsymSignatureAlgorithms.RSA_SHA256.getURI () + "'];\n" +
        "        invoke_object." + CERTIFICATE_FILTERS_JSON + " = " + SignatureDemoService.certificate_filter_js + ";\n" +
        "        var object_to_sign = invoke_object." + OBJECT_TO_SIGN_JSON + " = {};\n" +
        "        object_to_sign." + MIME_TYPE_JSON + " = '" + mime_type + "';\n" +
        "        object_to_sign." + DOCUMENT_JSON + " = '" + getBinaryArray (html_flag, date_string) + "';\n" +
        "        var signature_request = JSON.stringify(invoke_object);\n" +
        "        document.getElementById('request').value = signature_request;  // Demo purposes only...\n" +
        "        setTimeout(function(){\n" +
        "            event.source.postMessage(signature_request, event.origin);\n" +
//      "        }, " + (SIGNATURE_TIMEOUT_INIT + 1000) + ");\n" +
        "        }, 500);\n" +
        "        message_state = '" + Messages.SIGNATURE_RESPONSE + "';\n" +
        "    } else {\n" +
        "        document.getElementById('signature').value = JSON.stringify(received_json);\n" +
        "        setTimeout(function(){\n" +
        "            document.forms.shoot.submit();\n" +
        "        }, 0);\n" +
        "    }\n" +
        "}, false);\n", null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                getIframeHTML() +
                "<form name=\"shoot\" method=\"POST\" action=\"signedresult\">" +
                "<input type=\"hidden\" name=\"signature\" id=\"signature\">" +
                "<input type=\"hidden\" name=\"request\" id=\"request\">" +
                "</form></td></tr>"));
      }

    public static void signatureFrame (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, getHTMLSignatureFrameSource ());
      }

    public static void signedResult (HttpServletResponse response, String message, String signature_request, boolean error, String title) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                "><form name=\"shoot\" action=\"showrequest\" method=\"POST\"><input type=\"hidden\" name=\"request\" value=\"" + HTMLEncoder.encode (signature_request) + "\"></form>" +
                 "<a style=\"z-order:3;position:absolute;right:10pt;top:10pt\" href=\"javascript:document.shoot.submit()\">Show Signature Request</a",
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table><tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Resulting " + 
                (error ? "[Invalid]" : "[Valid]") +
                " Signature<br>&nbsp;</td></tr><tr><td>" +
                (error ? "<span style=\"font-size:10pt;color:red\">" + HTMLEncoder.encode (message) + "</span>" : 
                  "<div title=\"" + title + "\" style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;max-width:800pt;padding:10pt;word-wrap:break-word;box-shadow:3pt 3pt 3pt #D0D0D0;\">" +
                  message + "</div>") +
                "</td></tr></table></td></tr>"));
      }

    public static void signatureCommandPage (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null, null,
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table><tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Select Signature Parameters<br>&nbsp;</td></tr>" +
            "<tr><td align=\"center\"><table><tr><td>Note that most real signature systems assume that you:<br>1) are authenticated<br>" +
            "2) fill in a form in an interactive process<br></td></tr>" +
            "<tr><td>Since this is outside of the actual signature application, the demo "+
            "does<br>not implement these steps, it rather goes directly to the core " +
            "by providing<br>already filled-in forms.<br>&nbsp;</td></tr>" +
            "<tr><td>BTW, <span style=\"color:red\">the PIN code is 1234</span>.<br>&nbsp;</td></tr>" +
            "</table></td></tr>" +
            "<tr><td align=\"center\"><form method=\"POST\" action=\"signcmd\"><table class=\"tftable\">" +
            "<tr><td rowspan=\"2\">Document Type</td>" +
            "<td><input type=\"radio\" name=\"doctype\" checked value=\"html\">&nbsp;HTML</td>" +
            "</tr><tr><td><input type=\"radio\" name=\"doctype\" value=\"pdf\">&nbsp;PDF</td></tr>" +
            "<tr><td rowspan=\"3\">Signature format</td>" +
            "<td><input type=\"radio\" name=\"sigfmt\" checked value=\"jcs\">&nbsp;JSON (JCS)</td></tr>" +
            "<tr><td><input type=\"radio\" name=\"sigfmt\" value=\"jws\">&nbsp;JOSE (JWS)</td></tr>" +
            "<tr><td><input type=\"radio\" name=\"sigfmt\" value=\"xml\">&nbsp;XML DSig</td></tr>" +
            "<tr><td rowspan=\"2\">Signature Type</td>" +
            "<td><input type=\"radio\" name=\"sigtype\" checked value=\"det\">&nbsp;Detached</td></tr>" +
            "<tr><td><input type=\"radio\" name=\"sigtype\" value=\"emb\">&nbsp;Embedding</td></tr>" +
            "<tr><td colspan=\"2\" style=\"text-align:center\"><input type=\"submit\" class=\"stdbtn\" value=\"Continue..\"></td></tr>" +
            "</table></form></td></tr>" +
            "</table></td></tr>"));
      }

    public static void showSignatureRequest (HttpServletResponse response, String signature_request, boolean error) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,null,
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table><tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Signature Request<br>&nbsp;</td></tr><tr><td>" +
            (error ? "<span style=\"font-size:10pt;color:red\">" + HTMLEncoder.encode (signature_request) + "</span>" : 
              "<div style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;max-width:800pt;padding:10pt;word-wrap:break-word;box-shadow:3pt 3pt 3pt #D0D0D0;\">" +
              signature_request + "</div>") +
            "</td></tr></table></td></tr>"));
      }
  }
