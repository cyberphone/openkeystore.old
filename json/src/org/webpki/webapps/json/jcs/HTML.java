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
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HTML
  {
    static final String SIGNUP_BGND_COLOR   = "#F4FFF1";
    static final String SIGNUP_EDIT_COLOR   = "#FFFA91";
    static final String SIGNUP_BAD_COLOR    = "#F78181";
    static final String BOX_SHADDOW         = "box-shadow:5px 5px 5px #C0C0C0";
    static final String KG2_DEVID_BASE      = "Field";
    static final String HOME = "><a href=\"home\" title=\"Home\" style=\"position:absolute;top:15px;right:15px;z-index:5;visibility:visible\">Home</a";

    static final String STATIC_BOX = "word-wrap:break-word;width:800pt;background:#F8F8F8;";
    static final String COMMON_BOX = "border-width:1px;border-style:solid;border-color:grey;padding:10pt;box-shadow:3pt 3pt 3pt #D0D0D0";

    static final String TEXT_BOX   = "background:#FFFFD0;width:805pt;";
    
    static final String SAMPLE_DATA = "{\n" + 
                                      "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\n" +
                                      "  &quot;otherProperties&quot;: [2000, true]\n" +
                                      "}";
    
    static final String HTML_INIT = 
        "<!DOCTYPE html>"+
        "<html><head><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
        "<title>JSON Signature Demo</title>"+
        "<style type=\"text/css\">html {overflow:auto} html, body {margin:0px;padding:0px;height:100%} "+
        "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white} "+
        "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica} "+
        "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica} "+
        "a {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} "+
        "input {font-weight:normal;font-size:8pt;font-family:verdana,arial} "+
        "td {font-size:8pt;font-family:verdana,arial} "+
        ".smalltext {font-size:6pt;font-family:verdana,arial} "+
        "button {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px} "+
        ".headline {font-weight:bolder;font-size:10pt;font-family:arial,verdana} " +
        "</style>";
    

    static String encode (String val)
      {
        if (val != null)
          {
            StringBuffer buf = new StringBuffer (val.length () + 8);
            char c;

            for (int i = 0; i < val.length (); i++)
              {
                c = val.charAt (i);
                switch (c)
                  {
                    case '<':
                      buf.append ("&lt;");
                      break;
                    case '>':
                      buf.append ("&gt;");
                      break;
                    case '&':
                      buf.append ("&amp;");
                      break;
                    case '\"':
                      buf.append ("&#034;");
                      break;
                    case '\'':
                      buf.append ("&#039;");
                      break;
                    default:
                      buf.append (c);
                      break;
                  }
              }
            return buf.toString ();
          }
        else
          {
            return new String ("");
          }
      }
    
    static String newLines2HTML (String text_with_newlines)
      {
        StringBuffer result = new StringBuffer ();
        for (char c : text_with_newlines.toCharArray ())
          {
            if (c == '\n')
              {
                result.append ("<br>");
              }
            else
              {
                result.append (c);
              }
          }
        return result.toString ();
      }
    
    static String getHTML (String javascript, String bodyscript, String box)
      {
        StringBuffer s = new StringBuffer (HTML_INIT);
        if (javascript != null)
          {
            s.append ("<script type=\"text/javascript\">").append (javascript).append ("</script>");
          }
        s.append ("</head><body");
        if (bodyscript != null)
          {
            s.append (' ').append (bodyscript);
          }
        s.append ("><div style=\"position:absolute;top:15pt;left:15pt;z-index:5;visibility:visible\">" +
                  "<a href=\"http://webpki.org\" title=\"WebPKI.org\"><img src=\"images/webpki-logo.gif\" style=\"border-width:1px;border-style:solid;border-color:blue;box-shadow:3pt 3pt 3pt #D0D0D0\" alt=\"WebPKI.org logo...\"></a></div>" +
                  "<table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\">").append (box).append ("</table></body></html>");
        return s.toString ();
      }
    
    static void output (HttpServletResponse response, String html) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write (html.getBytes ("UTF-8"));
      }

    static String getConditionalParameter (HttpServletRequest request, String name)
      {
        String value = request.getParameter (name);
        if (value == null)
          {
            return "";
          }
        return value;
      }

    public static String fancyBox (String id, String content)
      {
        return "<div id=\"" + id + "\" style=\"" + STATIC_BOX + COMMON_BOX + "\">" + content + "</div>";
      }

    public static String fancyText (int rows, String content)
      {
        return "<textarea style=\"margin-top:3pt;" + TEXT_BOX + COMMON_BOX + "\" rows=\"" + rows + 
               "\" maxlength=\"100000\" name=\"" + RequestServlet.JCS_ARGUMENT + "\">" + content +
               "</textarea>";
      }
    
    public static void homePage (HttpServletResponse response, String baseurl) throws IOException, ServletException
      {
        String request_url =  baseurl + "/request";
        HTML.output (response, HTML.getHTML (null,
                null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width=\"300px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JCS - JSON Cleartext Signature<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a href=\"" + baseurl + "/verify\">Verify a JCS on the server</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a href=\"" + baseurl + "/create\">Create a JCS on the server</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><i>Experimental:</i> <a href=\"" + baseurl + "/webcrypto\">Create a JCS using WebCrypto</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">URL for testing with a client device: <a href=\"" + request_url + "\">" + request_url + "</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a target=\"_blank\" href=\"https://cyberphone.github.io/openkeystore/resources/docs/jcs.html\">JCS Documentation</a></td></tr>" +
                 "</table></td></tr>"));
      }

    public static void verifyPage (HttpServletResponse response, HttpServletRequest request, String signature) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                HOME,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table cellpadding=\"0\" cellspacing=\"0\"><form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">"  +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Testing JSON Signatures<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">Paste a JSON signature in the text box or try with the default:</td></tr>" +
                   "<tr><td align=\"left\">" + fancyText (20, encode (signature)) + "</td></tr>" +
                   "<tr><td align=\"center\">&nbsp;<br><input type=\"submit\" value=\"Verify JSON Signature!\" name=\"sumbit\"></td></tr>" +
                 "</form></table></td></tr>"));
      }
    
    private static String webCryptoGenerateJS ()
      {
        return
        "          document.getElementById ('pub.key').innerHTML = fancyDiv ('Generated public key in JCS format',\n" +
        "              new org.webpki.json.JSONObjectWriter ().setPublicKey (publicKeyInX509Format).serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_HTML)) +\n" +
        "              '<br>&nbsp;<br>Editable sample data in JSON Format:<br>' + \n" +
        "              '<textarea style=\"margin-top:3pt;margin-left:0pt;padding:10px;background:#FFFFD0;min-width:805pt;border-width:1px;border-style:solid;border-color:grey;box-shadow:3pt 3pt 3pt #D0D0D0\" ' +\n" +
        "              'rows=\"5\" maxlength=\"1000\" id=\"json.text\">" + javaScript (SAMPLE_DATA) + "</textarea>' +\n" +
        "              '<p><input type=\"button\" value=\"Sign Sample Data\" onClick=\"signSampleData ()\"/></p><p id=\"sign.res\"><p>';\n";

      }

    private static String javaScript (String string)
      {
        StringBuffer s = new StringBuffer ();
        for (char c : string.toCharArray ())
          {
            if (c == '\n')
              {
                s.append ("\\n");
              }
            else
              {
                s.append (c);
              }
          }
        return s.toString ();
      }

    public static void webCryptoPage (HttpServletResponse response, String verify_base, boolean msie_flag) throws IOException, ServletException
      {
        StringBuffer html = new StringBuffer (
            "<!DOCTYPE html>\n<html><head><title>WebCrypto/JCS Demo</title><style> " +
             "a {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} " +
             "</style></head>\n" +
            "<body style=\"padding:10pt;font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white\"" + HOME + ">\n" +
            "<h3>WebCrypto / JCS Demo</h3>\n\n" +
            "<p><input type=\"button\" value=\"Create Key\" onClick=\"createKey ()\"/></p>\n\n" +
            "<div id=\"pub.key\"></div>\n\n" +
            "<!-- WebPKI's JSON Encoder/Decoder/Validator/Signer/Verifier -->\n" +
            "<script src=\"libjson.js\"></script>\n\n" +
            "<script>\n\n  // ");
        html.append (msie_flag ? 
              "This code is tailored for MSIE 11 (early implementation)\n\nvar crypto = window.crypto || window.msCrypto;" 
                                 : 
              "This code is supposed to be compliant with the WebCrypto draft...")
          .append ("\n\n" +
        
              "var pubKey;\n" +
              "var privKey;\n" +
              "var signatureWriter;\n" +
              "var publicKeyInX509Format; // The bridge between JCS and WebCrypto\n\n" +
    
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Nice-looking text-boxes                                              //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "function fancyDiv (header, content) {\n" +
              "    return header + ':<br><div style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;\\\n" + 
              "           max-width:800pt;padding:10pt;word-wrap:break-word;box-shadow:3pt 3pt 3pt #D0D0D0\">' + content + '</div>';\n" +
              "}\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Error message helper                                                 //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
             "function bad (id, message) {\n" +
              "    document.getElementById (id).innerHTML = '<b style=\"color:red\">' + message + '</b>';\n" +
              "}\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Create key event handler                                             //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "function createKey () {\n" +
              "    console.log ('Begin creating key...');\n" +
              "    document.getElementById ('pub.key').innerHTML = '<i>Working...</i>';\n")
            .append (msie_flag ?
              "    var genOp = crypto.subtle.generateKey ({name: \"RSASSA-PKCS1-v1_5\", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n" +
              "                                         false,\n" +
              "                                         [\"sign\", \"verify\"]);\n\n" +
              "    genOp.onerror = function (e) {\n" +
              "        bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
              "    }\n\n" +

              "    genOp.oncomplete = function (e) {\n" +
              "        pubKey = e.target.result.publicKey;\n" +
              "        privKey = e.target.result.privateKey;\n\n" +

              "        var expOp = crypto.subtle.exportKey ('spki', pubKey);\n\n" +

              "        expOp.onerror = function (e) {\n" + 
              "            bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
              "        }\n\n" +

              "        expOp.oncomplete = function (evt) {\n" +
              "            publicKeyInX509Format = new Uint8Array (evt.target.result);\n" +
              "            console.log ('generateKey() RSASSA-PKCS1-v1_5: PASS');\n" +
               webCryptoGenerateJS () +
              "        }\n\n" +
              "    }" 
                  : 
              "  crypto.subtle.generateKey ({name: \"RSASSA-PKCS1-v1_5\", hash: {name: \"SHA-256\"}, modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n" +
              "                               false,\n" +
              "                               [\"sign\", \"verify\"]).then (function (key) {\n" +
              "      pubKey = key.publicKey;\n" +
              "      privKey = key.privateKey;\n\n" +

              "      crypto.subtle.exportKey ('spki', pubKey).then (function (key) {\n" +
              "          publicKeyInX509Format = new Uint8Array (key);\n" +
              "          console.log ('generateKey() RSASSA-PKCS1-v1_5: PASS');\n" +
               webCryptoGenerateJS () +
              "        });\n" +
              "    }).then (undefined, function () {\n" + 
              "        bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
              "    });");
        html.append ("\n}\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// JCS callback functions                                               //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "var JCSSigner = function () {\n" +
              "};\n\n" +

              "/* String */ JCSSigner.prototype.getAlgorithm = function () {\n" +
              "    // Every crypto-system with some self-estem defines their own algorithm IDs, right?\n" +
              "    // But in the demo we used JOSE since JCS has been upgraded to support this as well...\n" +
              "    return 'RS256';\n" +
              "};\n\n" +

              "/* JSONSignatureTypes */JCSSigner.prototype.getSignatureType = function () {\n" +
              "    return org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY;\n" +
              "};\n\n" +

              "/* String */JCSSigner.prototype.getKeyId = function () {\n" +
              "    return null;\n" +
              "};\n\n" +

              "/* Uint8Array */ JCSSigner.prototype.getPublicKey = function () {\n" +
              "    return publicKeyInX509Format;\n" +
              "};\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Sign event handler                                                   //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "function signSampleData () {\n" +
              "    try {\n" +
              "        signatureWriter = new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse (document.getElementById ('json.text').value));\n" +
              "    } catch (err) {\n" +
              "        bad ('sign.res', 'JSON error: ' + err.toString ());\n" +
              "        return;\n" +
              "    }\n\n")
 
          .append (msie_flag ?
              "    var signer = crypto.subtle.sign ({name: \"RSASSA-PKCS1-v1_5\",\n" +
              "                                      hash: \"SHA-256\"},\n" +
              "                                      privKey,\n" +
              "                                      signatureWriter.beginSignature (new JCSSigner ()));\n\n" +

              "    signer.onerror = function (evt) {\n" +
              "        bad ('sign.res', 'WebCrypto failed for unknown reasons');\n" +
              "    }\n\n" +

              "    signer.oncomplete = function (evt) {\n" +
              "        var signatureValue = new Uint8Array (evt.target.result);\n" +
              "        console.log ('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n" +
              outputSignature () +
              "    }" 
                :
              "    crypto.subtle.sign ({name: \"RSASSA-PKCS1-v1_5\"},\n" +
              "                        privKey,\n" +
              "                        signatureWriter.beginSignature (new JCSSigner ())).then (function (signature) {\n" +
              "        var signatureValue = new Uint8Array (signature);\n" +
              "        console.log ('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n" +
              outputSignature () +
              "    }).then (undefined, function () {\n" +
              "        bad ('sign.res', 'WebCrypto failed for unknown reasons');\n" +
              "    });")
         .append ("\n}\n\n" +
              verifySignature (verify_base));
             
        HTML.output (response, html.append ("</script></body></html>").toString ());
      }

    private static String verifySignature (String verify_base)
      {
        return 
            "//////////////////////////////////////////////////////////////////////////\n" +
            "// Optional validation is in this demo/test happening on the server     //\n" +
            "//////////////////////////////////////////////////////////////////////////\n" +
            "function verifySignatureOnServer () {\n" +
            "    document.location.href = '" + verify_base + "' +\n" +
            "        org.webpki.util.Base64URL.encode (org.webpki.util.ByteArray.convertStringToUTF8 (signatureWriter.serializeJSONObject (org.webpki.json.JSONOutputFormats.NORMALIZED)));\n" +
            "}\n";
      }

    private static String outputSignature ()
      {
        return "      document.getElementById ('sign.res').innerHTML = fancyDiv ('Signed data in JCS format',\n" +
               "          signatureWriter.endSignature (signatureValue).serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_HTML)) +\n" +
               "          '<p><input type=\"button\" value=\"Verify Signature (on the server)\" onClick=\"verifySignatureOnServer ()\"></p>';\n";
      }

    public static void errorPage (HttpServletResponse response, String error) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
              HOME,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width=\"300px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana;color:red\">Something went wrong...<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">" + newLines2HTML (encode (error)) + "</td></tr>" +
                 "</table></td></tr>"));
      }

    public static void printResultPage (HttpServletResponse response, String message) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                                            HOME,
                                             "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" + message + "</td></tr>"));
      }

    public static void createPage (HttpServletResponse response, HttpServletRequest request) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
            HOME,
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<table cellpadding=\"0\" cellspacing=\"0\"><form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">"  +
               "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JSON Signature Creation<br>&nbsp;</td></tr>" +
               "<tr><td align=\"left\">Paste an unsigned JSON object in the text box or try with the default:</td></tr>" +
               "<tr><td align=\"left\">" + fancyText (10,
                         "{\n" + "" +
                         "  &quot;statement&quot;: &quot;Hello signed world!&quot;,\n" +
                         "  &quot;otherProperties&quot;: [2000, true]\n" +
                         "}") +
                     "</td></tr>" +
               "<tr><td align=\"center\"><table>" +
                 "<tr><td valign=\"middle\" rowspan=\"5\">Select signing key:&nbsp;</td><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + GenerateSignature.ACTION.SYM + 
                 "\">Symmetric key</td><td>" +
                 "<tr><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + GenerateSignature.ACTION.EC + "\" checked=\"checked\">EC Key (P-256)</td><td>" +
                 "<tr><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + GenerateSignature.ACTION.RSA + "\">RSA Key (2048)</td><td>" +
                 "<tr><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + GenerateSignature.ACTION.X509 + "\">X.509 Certificate/Private key</td><td>" +
                 "<tr><td align=\"left\"><input type=\"checkbox\" name=\"" + CreateServlet.JOSE_FLAG + "\" checked value=\"true\">JOSE Algorithms</td><td>" +
                 "</table></td></tr>" +
               "<tr><td align=\"center\">&nbsp;<br><input type=\"submit\" value=\"Create JSON Signature!\" name=\"sumbit\"></td></tr>" +
             "</form></table></td></tr>"));
      }

    public static void browserCheck (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, "<!DOCTYPE html><html><head><title>WebCrypto and JCS Demo</title>" +
        "</head><body style=\"padding:10pt;font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white\">Finding browser..." +
        "<script>\n" +
        "var d = new Date();\n" +
        "d.setTime(d.getTime()+(60*60*1000));\n" +
        "if (window.crypto !== undefined && window.crypto.subtle !== undefined) {\n" +
        "    console.log ('WebCrypto Support');\n" +
        "    document.cookie = '" + WebCryptoServlet.BROWSER_COOKIE + "=" + WebCryptoServlet.STD + "; expires=' + d.toGMTString();\n" +
        "}\n" +
        "else if (window.crypto === undefined && window.msCrypto !== undefined) {\n" +
        "    console.log ('MSIE 11');\n" +
        "    document.cookie = '" + WebCryptoServlet.BROWSER_COOKIE + "=" + WebCryptoServlet.MSIE + "; expires=' + d.toGMTString();\n" +
        "}\n" +
        "document.location.reload ();\n" + 
        "</script></body></html>");
      }
  }
