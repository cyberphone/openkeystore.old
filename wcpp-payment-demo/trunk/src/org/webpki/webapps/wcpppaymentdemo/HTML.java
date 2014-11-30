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
package org.webpki.webapps.wcpppaymentdemo;

import java.io.IOException;

import java.util.Vector;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONSignatureDecoder;

public class HTML implements BaseProperties
  {
    static final int PAYMENT_WINDOW_WIDTH            = 450;
    static final int PAYMENT_WINDOW_HEIGHT           = 250;
    static final int PAYMENT_LOADING_SIZE            = 48;
    static final int PAYMENT_DIV_HORIZONTAL_PADDING  = 6;
    static final int PAYMENT_DIV_VERTICAL_PADDING    = 5;
    static final String PAYMENT_BORDER_COLOR         = "#306754";
    static final int PAYMENT_PAN_PADDING_TOP         = 5;
    static final int PAYMENT_PAN_PADDING_BOTTOM      = 10;
    static final int PAYMENT_CARD_HORIZ_GUTTER       = 20;
    static final int PAYMENT_CARD_RIGHT_MARGIN       = 30;
    static final int PAYMENT_CARD_TOP_POSITION       = 25;
    static final int PAYMENT_BUTTON_LEFT             = 15;
    
    static final int PIN_MAX_LENGTH                  = 20;
    static final int PIN_FIELD_SIZE                  = 8;

    static final int PAYMENT_TIMEOUT_INIT            = 5000;
    
    static final String FONT_VERDANA = "Verdana,'Bitstream Vera Sans','DejaVu Sans',Arial,'Liberation Sans'";
    static final String FONT_ARIAL = "Arial,'Liberation Sans',Verdana,'Bitstream Vera Sans','DejaVu Sans'";
    
    static final String HTML_INIT = 
        "<!DOCTYPE html>"+
        "<html><head><meta charset=\"UTF-8\"><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
//        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
        "<title>WebCrypto++ Payment Demo</title>"+
        "<style type=\"text/css\">html {overflow:auto}\n"+
        ".tftable {border-collapse:collapse;box-shadow:3pt 3pt 3pt #D0D0D0}\n" +
        ".tftable th {font-size:10pt;background:" +
          "linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);" +
          "border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color:#a9a9a9;" +
          "text-align:center;font-family:" + FONT_ARIAL + "}\n" +
        ".tftable td {background-color:#FFFFE0;font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;font-family:" + FONT_ARIAL + "}\n" +
        "body {font-size:10pt;color:#000000;font-family:" + FONT_VERDANA + ";background-color:white}\n" +
        "a {font-weight:bold;font-size:8pt;color:blue;font-family:" + FONT_ARIAL + ";text-decoration:none}\n" +
        "td {font-size:8pt;font-family:" + FONT_VERDANA + "}\n" +
        ".quantity {text-align:right;font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".updnbtn {vertical-align:middle;text-align:center;font-weight:normal;font-size:8px;font-family:" + FONT_VERDANA + ";margin:0px;border-spacing:0px;padding:2px 3px 2px 3px}\n";
    
    static String getIframeHTML ()
      {
        return "<iframe src=\"" + PaymentDemoService.bank_url +
               "/payment\" style=\"width:" + PAYMENT_WINDOW_WIDTH + 
               "px;height:" + PAYMENT_WINDOW_HEIGHT + 
               "px;border-width:1px;border-style:solid;border-color:" +
               PAYMENT_BORDER_COLOR + 
               ";box-shadow:3pt 3pt 3pt #D0D0D0\"></iframe>";
      }

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
         .append (PaymentDemoService.bank_url)
         .append ("'\" title=\"Home sweet home...\" style=\"cursor:pointer;position:absolute;top:15px;left:15px;z-index:5;visibility:visible;padding:5pt 8pt 5pt 8pt;font-size:12pt;text-align:center;background: radial-gradient(ellipse at center, rgba(255,255,255,1) 0%,rgba(242,243,252,1) 38%,rgba(196,210,242,1) 100%);border-radius:8pt;border-width:1px;border-style:solid;border-color:#B0B0B0;box-shadow:3pt 3pt 3pt #D0D0D0;}\">" +
         "WebCrypto++<br><span style=\"font-size:8pt\">Payment Demo Home</span></div>" + "<table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\">")
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

    public static void homePage (boolean crypto_enabled, HttpServletResponse response) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer ("function checkWebCryptoSupport() {\n");
        if (PaymentDemoService.web_crypto)
          {
            s.append (
            "    if (window.crypto && window.crypto.subtle) {\n" +
            "        crypto.subtle.importKey('jwk',")
            .append (PaymentDemoService.client_private_key.getJWK ())
            .append (", {name: '")
            .append (PaymentDemoService.client_private_key.getKeyType ().equals ("EC") ? "ECDSA'" : "RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}")
            .append ("}, true, ['sign']).then (function(private_key) {\n            ")
            .append (crypto_enabled ? "console.debug('Running in WebCrypto Mode!');\n" : "document.location.href = 'cryptohome';\n")
            .append (
            "        }).then (undefined, function() {")
            .append (crypto_enabled ? "document.location.href = 'home'" : "console.debug('Non-WebCrypto Mode')")
            .append (
                "});\n" +
            "    } else {\n" +
            "        ")
            .append (crypto_enabled ? "document.location.href = 'home'" : "console.debug('Non-WebCrypto Mode')")
            .append (";\n    }\n");
          }
        else 
          {
            s.append (crypto_enabled ? "    document.location.href = 'home';\n" : "    console.debug('Non-WebCrypto Mode');\n");
          }
        HTML.output (response, HTML.getHTML (s.append ("}\n").toString (), "onload=\"checkWebCryptoSupport()\"",
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width:600px;\" cellpadding=\"4\">" +
                   "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">WebCrypto++ Payment Demo<br>&nbsp;</td></tr>" +
                   "<tr><td style=\"text-align:left\">This application is a demo of what a true WebCrypto++ implementation " +
                   "could offer for <span style=\"color:red\">decentralized payment systems</span>.</td></tr>" +
                   "<tr><td style=\"text-align:left\">In particular note the <span style=\"color:red\">automatic payment card discovery</span> process " +
                   "and that <span style=\"color:red\">payment card logotypes are personalized</span> since they "+
                   "are read from the user's local credential-store.</td></tr>" +
                   "<tr><td>By applying <span style=\"color:red\">3D Secure</span> like methods and <span style=\"color:red\">EMV tokenization</span>, there is no need for " +
                   "handing over static credit-card information to merchants.</td></tr>" +
                   "<tr><td style=\"text-align:left\">For protecting the user's privacy, <span style=\"color:red\">user-related data is encrypted</span> and only readable " +
                   "by the payment-provider who issued the specific payment card.</td></tr>" +
                   "<tr><td style=\"text-align:left\">Although the demo is <i>partially</i> a mockup (no &quot;polyfill&quot; in the world can replace WebCrypto++), " +
                   "the IFRAME solution and cross-domain communication using <code>postMessage()</code> should be pretty close to that of a real system.</td></tr>" +
                   "<tr><td style=\"text-align:left\"><i>In case you are testing with a WebCrypto-enabled browser, the user-authorization will be signed and encrypted " +
                   "which can viewed in a browser debugger window.</i></td></tr>" +
                   "<tr><td align=\"center\"><table cellspacing=\"0\">" +
                   "<tr style=\"text-align:left\"><td><a href=\"" + PaymentDemoService.bank_url + "/cards\">Initialize Payment Cards&nbsp;&nbsp;</a></td><td><i>Mandatory</i> First Step</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a href=\"" + PaymentDemoService.merchant_url + "\">Go To Merchant</a></td><td>Shop Til You Drop!</td></tr>" +
                   "<tr><td style=\"text-align:center;padding-top:15pt;padding-bottom:5pt\" colspan=\"2\"><b>Documentation</b></td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/pki-webcrypto.pdf\">WebCrypto++</a></td><td><i>Conceptual</i> Specification</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/EMV-Tokenization-SET-3DSecure-WebCryptoPlusPlus-combo.pdf#page=4\">Demo Payment System</a></td><td>State Diagram Etc.</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://code.google.com/p/openkeystore/source/browse/#svn/wcpp-payment-demo\">Demo Source Code</a></td><td>For Nerds...</td></tr>" +
                   "<tr><td style=\"text-align:center;padding-top:15pt;padding-bottom:5pt\" colspan=\"2\"><b>Related Applications</b></td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://mobilepki.org/jcs\">JCS</a></td><td>JSON Cleartext Signature</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://play.google.com/store/apps/details?id=org.webpki.mobile.android\">SKS/KeyGen2</a></td><td>Android PoC</td></tr>" +
                   "<tr style=\"text-align:left\"><td><a target=\"_blank\" href=\"https://mobilepki.org/WCPPSignatureDemo\">User Signatures</a></td><td>WebCrypto++ Signature Demo</td></tr>" +
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

    public static void paymentPage (HttpServletResponse response, HttpServletRequest request) throws IOException, ServletException
      {
        boolean web_crypto = HomeServlet.isWebCryptoEnabled (request);
        StringBuffer s = new StringBuffer (
        "<!DOCTYPE html>"+
        "<html><head><meta charset=\"UTF-8\">"+
        "<style type=\"text/css\">html {overflow:hidden}\n"+
        "body {font-size:10pt;color:#000000;font-family:" + FONT_ARIAL + ";background-color:white;margin:0px;padding:0px}\n" +
        "table {border-collapse: collapse}\n" +
        "td {padding: 0px}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + ";position:relative;visibility:hidden}\n" +
        "</style><script type=\"text/javascript\">\n" +
        "\"use strict\";\n\n" +
        "////////////////////////////////////////////////////////////////////\n" +
        "// Disclaimer: The actual messages used by this payment provider  //\n" +
        "// in no way represent a standard or a standards proposal.        //\n" +
        "// However, the message flow is anticipated to be usable \"as is\". //\n" +
        "////////////////////////////////////////////////////////////////////\n\n" +
        "var webpki = {};  // For our custom objects\n\n" +
        "var aborted_operation = false;\n" +
        "var pin_error_count = 0;\n" +
        "var selected_card;\n" +
        "var authorize_command;\n" +
        "var encrypted_data;\n" +
        "var encrypted_key;\n" +
        "var encryption_algorithm;\n" +
        "var timeouter_handle = null;\n" +
        "var request_amount;\n" +
        "var request_reference_id;\n" +
        "var request_date_time;\n" +
        "var caller_common_name;\n" +
        "var caller_domain;\n" +
        "var json_request;\n" +
        "\nwebpki.Currency = function(iso_name,symbol,first_position) {\n" +
        "    this.iso_name = iso_name;\n" +
        "    this.symbol = symbol;\n" +
        "    this.first_position = first_position;\n" +
        "};\n" +
        "var request_currency = null;\n" +
        "var currency_list = [];\n");
        for (Currencies currency : Currencies.values ())
          {
            s.append("currency_list.push(new webpki.Currency('")
            .append(currency.toString())
            .append("', '")
            .append(currency.symbol)
            .append("', ")
            .append(currency.first_position)
            .append ("));\n");
          }
        s.append ("\nwebpki.CardEntry = function(type, pin, pan, authorization_url, base64_image");
        if (web_crypto)
          {
            s.append (", bank_encryption_key, client_cert, client_private_key, cert_data");
          }
        s.append (
        ") {\n" +
        "    this.type = type;\n" +
        "    this.pin = pin;\n" +
        "    this.pan = pan;\n" +
        "    this.authorization_url = authorization_url;\n" +
        "    this.base64_image = base64_image;\n");
        if (web_crypto)
          {
            s.append (
                "    this.bank_encryption_key = bank_encryption_key;\n" +
                "    this.client_cert_path = [];\n" +
                "    this.client_cert_path.push(client_cert);\n" +
                "    this.client_private_key = client_private_key;\n" +
                "    this.cert_data = cert_data;\n");
          }
        s.append (
        "    this.matching = false;\n" +
        "};\n" +
        "var selected_card;\n" +
        "var card_list = [];\n");
        HttpSession session = request.getSession (false);
        if (session == null)
          {
            s.append ("console.debug('No web session found');\n");
          }
        else
          {
            @SuppressWarnings("unchecked")
            Vector<CardEntry> card_entries = (Vector<CardEntry>) session.getAttribute(CardEntry.CARD_LIST);
            if (card_entries != null)
            {
              s.append ("//\n// Since we have no WebCrypto++/SKS we [have to] cheat...\n//\n");
              for (CardEntry card_entry : card_entries)
                {
                    if (card_entry.active)
                    {
                        s.append("card_list.push(new webpki.CardEntry('")
                         .append(card_entry.card_type.toString())
                         .append("', '")
                         .append(card_entry.pin == null ? CardEntry.DEFAULT_PIN : card_entry.pin)
                         .append("', '")
                         .append(card_entry.pan)
                         .append("', '")
                         .append(card_entry.authorization_url)
                         .append("', '")
                         .append(card_entry.base64_image)
                         .append ("'");
                        if (web_crypto)
                          {
                            s.append (", ")
                             .append (card_entry.bank_encryption_key.getJWK ())
                             .append (", '")
                             .append (card_entry.client_certificate)
                             .append ("', ")
                             .append (card_entry.client_key.getJWK ())
                             .append (", ")
                             .append (card_entry.cert_data);
                          }
                        s.append ("));\n");
                    }
                }
            }
         }

        s.append ("\nvar BASE64URL = [" + 
          "'A','B','C','D','E','F','G','H'," +
          "'I','J','K','L','M','N','O','P'," +
          "'Q','R','S','T','U','V','W','X'," +
          "'Y','Z','a','b','c','d','e','f'," +
          "'g','h','i','j','k','l','m','n'," +
          "'o','p','q','r','s','t','u','v'," +
          "'w','x','y','z','0','1','2','3'," +
          "'4','5','6','7','8','9','-','_'];\n\n" +
         "function error(message) {\n" +
        "    console.debug('Error: ' + message);\n" +
        "    if (!aborted_operation) {\n" +
        "        document.getElementById('activity').innerHTML='ABORTED:<br>' + message;\n" +
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
        "   if (aborted_operation || window.self.innerWidth != " + PAYMENT_WINDOW_WIDTH + " || window.self.innerHeight != " + PAYMENT_WINDOW_HEIGHT + ") {\n" +
        "       error('Frame size manipulated by parent');\n" +
        "       return false;\n" +
        "   }\n" +
        "   if (!card_list.length) {\n" +
        "       error('You appear to have no payment cards at all, please return " +
            "to the <b>Payment&nbsp;Demo&nbsp;Home</b> and get some!  It\\'s free :-)');\n" +
        "       return false;\n" +
        "   }\n" +
        "   return true;\n" +
        "}\n\n" +
        "function checkTiming(milliseconds) {\n" +
        "   timeouter_handle = setTimeout(function() {error('Timeout')}, milliseconds);\n" +
        "}\n\n" +
        "function priceString(price_mult_100) {\n" +
        "    var price_number = Math.floor(price_mult_100 / 100) + '.' +  Math.floor((price_mult_100 % 100) / 10) +  Math.floor(price_mult_100 % 10);\n" +
        "    return request_currency.first_position ? request_currency.symbol + price_number : price_number + request_currency.symbol;\n" +  
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
        "function cardTableHeader(right_margin, top_margin) {\n" +
        "    return '<table style=\"" +
            "margin-left:auto;margin-right:' + right_margin + ';margin-top:' + top_margin + 'px\">';\n" +
        "}\n\n" +
        "function disableControls(disable) {\n" +
        "    document.getElementById('ok').disabled = disable;\n" +
        "    document.getElementById('pin').disabled = disable;\n" +
        "}\n\n" +
        "function showPINError(message) {\n" +
        "    disableControls(true);\n"+
        "    document.getElementById('pinerror').innerHTML = message;\n" +
        "    document.getElementById('pinerror').style.top = ((window.innerHeight - document.getElementById('pinerror').offsetHeight) / 2) + 'px';\n" +
        "    document.getElementById('pinerror').style.left = ((window.innerWidth - document.getElementById('pinerror').offsetWidth) / 2) + 'px';\n" +
        "    document.getElementById('pinerror').style.visibility = 'visible';\n" +
        "}\n\n" +
        "function closePINError() {\n" +
        "    document.getElementById('pinerror').style.visibility = 'hidden';\n" +
        "    disableControls(false);\n"+
        "    document.getElementById('pin').focus();\n" +
        "}\n\n" +
        "function outputCard(card_index, add_on) {\n" +
        "    return '<td>' + '" + 
             javaScript (CardEntry.CARD_DIV) +
             "' + card_list[card_index].base64_image + '\\')' + add_on + '\">" +
             "</div></td>';\n" +
        "}\n\n" +
        "function binaryToBase64URL(binarray) {\n" +
        "    var encoded = new String();\n" +
        "    var i = 0;\n" +
        "    var modulo3 = binarray.length % 3;\n" +
        "    while (i < binarray.length - modulo3) {\n" +
        "        encoded += BASE64URL[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += BASE64URL[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" +
        "        encoded += BASE64URL[((binarray[i++] << 2) & 0x3C) | ((binarray[i] >>> 6) & 0x03)];\n" +
        "        encoded += BASE64URL[binarray[i++] & 0x3F];\n" +
        "    }\n" +
        "    if (modulo3 == 1) {\n" +
        "        encoded += BASE64URL[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += BASE64URL[(binarray[i] << 4) & 0x30];\n" +
        "    }\n" +
        "    else if (modulo3 == 2) {\n" +
        "        encoded += BASE64URL[(binarray[i] >>> 2) & 0x3F];\n" +
        "        encoded += BASE64URL[((binarray[i++] << 4) & 0x30) | ((binarray[i] >>> 4) & 0x0F)];\n" +
        "        encoded += BASE64URL[(binarray[i] << 2) & 0x3C];\n" +
        "    }\n" +
        "    return encoded;\n" +
        "}\n\n" +
        "function convertStringToUTF8(string) {\n" +
        "    var buffer = [];\n" +
        "    for (var n = 0; n < string.length; n++) {\n" +
        "        var c = string.charCodeAt(n);\n" +
        "        if (c < 128) {\n" +
        "            buffer.push(c);\n" +
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
        "//\n" +
        "// Although PANs (card numbers) are not really needed from the user's\n" +
        "// point of view, they represent a legacy which should not be ignored...\n" +
        "//\n" +
        "function outputPAN(card_index) {\n" +
        "    var pan_html = '<td style=\"padding-top:" + PAYMENT_PAN_PADDING_TOP +
             "px;padding-bottom:" + PAYMENT_PAN_PADDING_BOTTOM + "px;font-size:8pt;font-family:" + javaScript (FONT_VERDANA) + ";text-align:center\">';\n" +
        "    var pan = card_list[card_index].pan;\n" +
        "    for (var i = 0; i < pan.length; i++) {\n" +
        "        if (i && i % 4 == 0) pan_html += ' ';\n" +
        "        pan_html += pan.charAt(i);\n" +
        "    }\n" +
        "    return pan_html + '</td>';\n" +
        "}\n\n" +
        "//\n" +
        "// This is the core display where the user authorizes the\n" +
        "// actual payment process.\n" +
        "//\n" +
        "function displayPaymentRequest(card_index) {\n" +
        "    selected_card = card_list[card_index];\n" +
        "    var payment_details = '<table id=\"details\" style=\"position:absolute;text-align:center\">" +
             "<tr><td>Requester: ' + caller_common_name + '</td></tr>" +
             "<tr><td style=\"padding-top:10pt;padding-bottom:10pt\">Amount: ' + priceString(request_amount) + '</td></tr>" +
             "<tr><td>PIN: <input id=\"pin\" " +
             "style=\"font-family:" + javaScript (FONT_VERDANA) + ";padding-left:3px;letter-spacing:2px;background-color:#f0f0f0\" " +
             "type=\"password\" size=\"" + PIN_FIELD_SIZE +
             "\" maxlength=\"" + PIN_MAX_LENGTH + "\"></td></tr>" +
             "<table>';\n" +
        "    document.getElementById('activity').innerHTML = '&nbsp;';\n" +
        "    document.getElementById('cancel').style.left = '" + PAYMENT_BUTTON_LEFT + "px';\n" +
        "    document.getElementById('content').innerHTML = payment_details + cardTableHeader('" +
             PAYMENT_CARD_RIGHT_MARGIN + "px', " +
             PAYMENT_CARD_TOP_POSITION + ") + " +
             "'<tr>' + outputCard(card_index, '\" title=\"Don\\'t leave home without it!') + '</tr>" +
             "<tr>' + outputPAN(card_index) + '</tr></table>';\n" +
        "    document.getElementById('details').style.top = (" +
             PAYMENT_WINDOW_HEIGHT + 
             " - document.getElementById('details').offsetHeight)/2 + 'px';\n" +
        "    var details_left = (" + (PAYMENT_WINDOW_WIDTH - CardEntry.CARD_WIDTH - PAYMENT_CARD_RIGHT_MARGIN) +
             " - document.getElementById('details').offsetWidth) / 2;\n" +
             "    document.getElementById('details').style.left = details_left + 'px';\n" +
             "    document.getElementById('ok').style.left = ((details_left + " +
                 "document.getElementById('pin').offsetLeft - " +
                 "document.getElementById('cancel').offsetWidth) * 2 + " +
                 "document.getElementById('pin').offsetWidth - " +
                 PAYMENT_BUTTON_LEFT + ") + 'px';\n" +
        "    document.getElementById('ok').style.visibility = 'visible';\n" +
        "    document.getElementById('pin').title = 'Forgot PIN? Try with ' + selected_card.pin + ' :-)';\n" +
        "    document.getElementById('pin').focus();\n" +
        "}\n\n" +
        "//\n" +
        "// Displays payee compatible cards for the user to select from.\n" +
        "// If the card collection does not fit in the selection frame,\n" +
        "// a vertically scrollable view is created.\n" +
        "//\n" +
        "function displayCompatibleCards(count) {\n" +
        "    document.getElementById('activity').innerHTML = 'Select Card:';\n" +
        "    var left_card = true;\n" +
        "    var previous_card;\n" +
        "    var cards = cardTableHeader('auto', count < 3 ? " + PAYMENT_CARD_TOP_POSITION + " : 0);\n" +
        "    for (var q = 0; q < card_list.length; q++) {\n" +
        "        if (card_list[q].matching) {\n"+
        "            cards += left_card ? '<tr>' : '<td style=\"width:" + PAYMENT_CARD_HORIZ_GUTTER + "px\"></td>';\n" +
        "            cards += outputCard(q, ';cursor:pointer\" title=\"Click to select\" onclick=\"displayPaymentRequest(' + q + ')');\n" +
        "            cards += left_card ? '' : '</tr>';\n" +
        "            if (left_card = !left_card) {\n" +
        "                cards += '<tr>' + outputPAN(previous_card) + '<td></td>' + outputPAN(q) + '</tr>';\n" +
        "            }\n" +
        "            previous_card = q;\n" +
        "        }\n" +
        "    }\n" +
        "    if (!left_card) {\n" +
        "        cards += '<td colspan=\"2\" rowspan=\"2\"></td><tr>' + outputPAN(previous_card) + '</tr>';\n" +
        "    }\n" +
        "    document.getElementById('content').innerHTML = cards + '</table>';\n" +
       "}\n\n" +
       "//\n" +
       "// Terminates the payment session in case of a user abort.\n" +
       "//\n" +
       "function userAbort() {\n" +
       "    document.getElementById('activity').innerHTML = 'Aborting...';\n" +
       "    document.getElementById('content').innerHTML = '';\n" +
       "    document.getElementById('busy').style.visibility = 'visible';\n" +
       "    window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" +
            Messages.ABORT + "')), window.document.referrer);\n" +
       "}\n\n");
        if (web_crypto)
          {
            s.append (
              "//\n" +
              "// Finally we send the authorization to the payee\n" +
              "//\n" +
              "function sendAuthorizationData(encrypted_authorization_data) {\n" +
              "    encrypted_data." + ALGORITHM_JSON + " = '" + SymEncryptionAlgorithms.AES256_CBC.getURI () + "';\n" +
              "    encrypted_data." + IV_JSON + " = binaryToBase64URL(encryption_algorithm.iv);\n" +
              "    encrypted_data." + ENCRYPTED_KEY_JSON + " = encrypted_key;\n" +
              "    encrypted_data." + CIPHER_TEXT_JSON + " = binaryToBase64URL(new Uint8Array(encrypted_authorization_data));\n" +
              "    window.parent.postMessage(JSON.stringify(authorize_command), window.document.referrer);\n" +
              "}\n\n" +
              "//\n" +
              "// RSA encrypted authorization\n" +
              "//\n" +
              "function performRSAEncryption(signed_auth_data) {\n" +
              "    var sym_alg = {name: 'AES-CBC', length: 256};\n" +
              "    crypto.subtle.generateKey(sym_alg, true, ['encrypt']).then (function(aes_key) {\n" +
              "    crypto.subtle.encrypt(encryption_algorithm, aes_key, signed_auth_data).then (function(encrypted_authorization_data) {\n" +
              "    crypto.subtle.exportKey('raw', aes_key).then (function(raw_aes_key) {\n" +
              "    var asym_alg = {name: 'RSA-OAEP', hash: {name: 'SHA-256'}};\n" +
              "    crypto.subtle.importKey('jwk', selected_card.bank_encryption_key, asym_alg, true, ['encrypt']).then (function(public_key) {\n" +
              "    crypto.subtle.encrypt(asym_alg, public_key, new Uint8Array(raw_aes_key)).then (function(encryped_aes_key) {\n" +
              "        encrypted_key." + ALGORITHM_JSON + " = '" + AsymEncryptionAlgorithms.RSA_OAEP_SHA256_MGF1P.getURI () + "';\n" +
              "        var public_key = {};\n" +
              "        encrypted_key." + JSONSignatureDecoder.PUBLIC_KEY_JSON + " = public_key;\n" +
              "        var rsa_key = {};\n" +
              "        public_key." + JSONSignatureDecoder.RSA_JSON + " = rsa_key;\n" +
              "        rsa_key." + JSONSignatureDecoder.MODULUS_JSON + " = selected_card.bank_encryption_key.n;\n" +
              "        rsa_key." + JSONSignatureDecoder.EXPONENT_JSON + " = selected_card.bank_encryption_key.e;\n" +
              "        encrypted_key." + CIPHER_TEXT_JSON + " = binaryToBase64URL(new Uint8Array(encryped_aes_key));\n" +
              "        sendAuthorizationData(encrypted_authorization_data);\n" +
              "    }).then (undefined, function() {error('Failed encrypting using public key')});\n" +
              "    }).then (undefined, function() {error('Failed import public key')});\n" +
              "    }).then (undefined, function() {error('Failed exporting symmetric key')});\n" +
              "    }).then (undefined, function() {error('Failed encrypting using symmetric key')});\n" +
              "    }).then (undefined, function() {error('Failed generating symmetric key')});\n" +
              "}\n\n" +
              "//\n" +
              "// ECDH JCS helper\n" +
              "//\n" +
              "function addECDHKey(name, jwk) {\n" +
              "    var public_key = encrypted_key[name] = {};\n" +
              "    var ec_key = public_key." + JSONSignatureDecoder.PUBLIC_KEY_JSON + " = {};\n" +
              "    var ec_params = ec_key." + JSONSignatureDecoder.EC_JSON + " = {};\n" +
              "    ec_params." + JSONSignatureDecoder.NAMED_CURVE_JSON + " = '" + KeyAlgorithms.NIST_P_256.getURI () + "';\n" +
              "    ec_params." + JSONSignatureDecoder.X_JSON + " = jwk.x;\n" +
              "    ec_params." + JSONSignatureDecoder.Y_JSON + " = jwk.y;\n" +
              "}\n\n" +
              "//\n" +
              "// ECDH KDF helper\n" +
              "//\n" +
              "function createBitString(string) {\n" +
              "    var utf8 = convertStringToUTF8('0' + string);\n" +
              "    utf8[0] = 0;\n" +
              "    return binaryToBase64URL(utf8);\n" +
              "}\n\n" +
              "//\n" +
              "// ECDH encrypted authorization\n" +
              "//\n" +
              "function performECDHEncryption(signed_auth_data) {\n" +
              "    var gen_alg = {name: 'ECDH', namedCurve: selected_card.bank_encryption_key.crv};\n" +
              "    crypto.subtle.generateKey(gen_alg, false, ['deriveKey']).then (function(key_pair) {\n" +
              "    crypto.subtle.exportKey('jwk', key_pair.publicKey).then (function(ephemeral_key) {\n" +
              "    crypto.subtle.importKey('jwk', selected_card.bank_encryption_key, {name: 'ECDH'}, false, ['deriveKey']).then (function(public_key) {\n" +
              "    // There should be a KDF here but it has not yet been implemented in Firefox...\n" +
              "    var derive_alg = {name: 'ECDH', public: public_key};\n" +
              "    crypto.subtle.deriveKey(derive_alg, key_pair.privateKey, {name: 'AES-CBC', length: 256}, false, ['encrypt']).then (function(aes_key) {\n" +
              "    crypto.subtle.encrypt(encryption_algorithm, aes_key, signed_auth_data).then (function(encrypted_authorization_data) {\n" +
              "        encrypted_key." + ALGORITHM_JSON + " = '" + ECDH_ALGORITHM_URI + "';\n" +
              "        var concat = encrypted_key." + KEY_DERIVATION_METHOD_JSON + " = {};\n" +
              "        concat."+ ALGORITHM_JSON + " = '" + CONCAT_ALGORITHM_URI + "';\n" +
              "        concat."+ HASH_ALGORITHM_JSON + " = '" + HashAlgorithms.SHA256.getURI () + "';\n" +
              "        // Demo parameters at this stage...\n" +
              "        concat."+ ALGORITHM_ID_JSON + " = createBitString('0');\n" +
              "        concat."+ PARTY_U_INFO_JSON + " = createBitString(caller_domain);\n" +
              "        concat."+ PARTY_V_INFO_JSON + " = createBitString(getDomainName(selected_card.authorization_url));\n" +
              "        addECDHKey('" + PAYMENT_PROVIDER_KEY_JSON + "', selected_card.bank_encryption_key);\n" +
              "        addECDHKey('" + EPHEMERAL_CLIENT_KEY_JSON + "', ephemeral_key);\n" +
              "        sendAuthorizationData(encrypted_authorization_data);\n" +
              "    }).then (undefined, function() {error('Failed encrypting')});\n" +
              "    }).then (undefined, function() {error('Failed deriving key')});\n" +
              "    }).then (undefined, function() {error('Failed import public key')});\n" +
              "    }).then (undefined, function() {error('Failed exporting public key')});\n" +
              "    }).then (undefined, function() {error('Failed generating key-pair')});\n" +
              "}\n\n");
          }
       s.append (
       "//\n" +
       "// This is the final part of the user authorization\n" +
       "//\n" +
       "function encryptAndSend(signed_auth_data) {\n" +
       "    authorize_command = createJSONBaseCommand('" + Messages.AUTHORIZE + "');\n" +
       "    authorize_command." + AUTH_URL_JSON + " = selected_card.authorization_url;\n" +
       "    encrypted_data = authorize_command." + AUTH_DATA_JSON + " = {};\n" +
       "    encrypted_data = encrypted_data." + ENCRYPTED_DATA_JSON + " = {};\n");
       if (web_crypto)
         {
           s.append (
             "    encrypted_key = {};\n" +
             "    encryption_algorithm = {\n" +
             "        name: 'AES-CBC',\n" +
             "        iv: crypto.getRandomValues(new Uint8Array(16))\n" +
             "    };\n" +
             "    if (selected_card.bank_encryption_key.kty == 'RSA') {\n" +
             "        performRSAEncryption(signed_auth_data);\n" +
             "    } else {\n" +
             "        performECDHEncryption(signed_auth_data);\n" +
             "    }\n");
         }
       else
         {
           s.append (
             "    // For a lame GUI-demo base64 is \"encryption\", right?\n" +
             "    encrypted_data." + CIPHER_TEXT_JSON + " = binaryToBase64URL(signed_auth_data);\n" +
             "    window.parent.postMessage(JSON.stringify(authorize_command), window.document.referrer);\n");
         }
       s.append (
       "}\n" +
       "//\n" +
       "// Called when the user authorized the payment.\n" +
       "//\n" +
       "function userAuthorize() {\n" +
       "    // Create \"" + AUTH_DATA_JSON + "\"\n" +
       "    var auth_data = {};\n" +
       "    auth_data." + PAYMENT_REQUEST_JSON + " = json_request;\n" +
       "    auth_data." + DOMAIN_NAME_JSON + " = caller_domain;\n" +
       "    auth_data." + CARD_TYPE_JSON + " = selected_card.type;\n" +
       "    auth_data." + PAN_JSON + " = selected_card.pan;\n" +
       "    var date_time = new Date().toISOString();\n" +
       "    if (date_time.indexOf('.') > 0 && date_time.indexOf('Z') > 0) {\n" +
       "        date_time = date_time.substring(0, date_time.indexOf('.')) + 'Z';\n" +
       "    }\n" +
       "    auth_data." + DATE_TIME_JSON + " = date_time;\n");
       if (web_crypto)
         {
           s.append (
             "    // Sign \"" + AUTH_DATA_JSON + "\"\n" +
             "    var signature_object = {};\n" +
             "    auth_data." + JSONSignatureDecoder.SIGNATURE_JSON + " = signature_object;\n" +
             "    signature_object." + JSONSignatureDecoder.ALGORITHM_JSON + " = '" + AsymSignatureAlgorithms.RSA_SHA256.getURI () + "';\n" +
             "    var key_import_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
             "    var key_sign_alg = key_import_alg;\n" +
             "    if (selected_card.client_private_key.kty == 'EC') {\n" +
             "        signature_object." + JSONSignatureDecoder.ALGORITHM_JSON + " = '" + AsymSignatureAlgorithms.ECDSA_SHA256.getURI () + "';\n" +
             "        key_import_alg = {name: 'ECDSA'};\n" +
             "        key_sign_alg = {name: 'ECDSA', hash: {name: 'SHA-256'}};\n" +
             "    }\n" +
             "    var key_info = {};\n" +
             "    signature_object." + JSONSignatureDecoder.KEY_INFO_JSON + " = key_info;\n" +
             "    key_info." + JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON + " = selected_card.cert_data;\n" +
             "    key_info." + JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON + " = selected_card.client_cert_path;\n");
         }
       s.append (
       "    var pin = document.getElementById('pin').value;\n" +
       "    if (pin_error_count < 3) {\n" +
       "        if (pin.length == 0) {\n" +
       "            showPINError('Please enter a PIN...');\n" +
       "            return;\n" +
       "        }\n" +
       "        if (selected_card.pin != pin) {\n" +
       "            if (++pin_error_count < 3) {\n" +
       "                showPINError('Incorrect PIN!<br>Attempts left: ' + (3 - pin_error_count));\n" +
       "                return;\n" +
       "            }\n" +
       "        }\n" +
       "    }\n" +
       "    if (pin_error_count == 3) {\n" +
       "        showPINError('Too many PIN errors,<br>the card is blocked!');\n" +
       "        return;\n" +
       "    }\n" +
       "    // Now we entered a critical phase and do not want to get interrupted!\n" +
       "    disableControls(true);\n"+
       "    document.getElementById('cancel').disabled = true;\n" +
       "    document.getElementById('busy').style.visibility = 'visible';\n");
       if (web_crypto)
         {
           s.append (
             "    crypto.subtle.importKey('jwk', selected_card.client_private_key, key_import_alg, false, ['sign']).then (function(private_key) {\n" +
             "    crypto.subtle.sign (key_sign_alg, private_key, convertStringToUTF8(JSON.stringify(auth_data))).then (function(signature) {\n" +
             "        signature_object." + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + " = binaryToBase64URL(new Uint8Array(signature));\n" +
             "        var json_auth_data = JSON.stringify(auth_data);\n" +
             "        console.debug('Unencrypted user authorization:\\n' + json_auth_data);\n" + 
             "        encryptAndSend(convertStringToUTF8(json_auth_data));\n" +
             "    }).then (undefined, function() {error('Failed signing')});\n" +
             "    }).then (undefined, function() {error('Failed importing private key')});\n");
         }
       else
         {
           s.append (
             "    var json_auth_data = JSON.stringify(auth_data);\n" +
             "    console.debug('Unencrypted user authorization:\\n' + json_auth_data);\n" + 
             "    encryptAndSend(convertStringToUTF8(json_auth_data));\n");
         }
       s.append (
       "}\n\n" +
       "//\n" +
       "// Processes payee's JSON response to the \"" + Messages.INITIALIZE + "\" message.\n");
       if (!web_crypto)
         {
           s.append ("// Note: In a genuine implementaion the \"" + PAYMENT_REQUEST_JSON + "\" object would be signed.\n");
         }
       s.append (
       "//\n" +
       "// Message syntax:\n" +
       "//   {\n" +
       "//     \"" + JSONDecoderCache.CONTEXT_JSON + "\": \"" + WCPP_DEMO_CONTEXT_URI + "\"\n" +
       "//     \"" + JSONDecoderCache.QUALIFIER_JSON + "\": \"" + Messages.INVOKE + "\"\n" +
       "//     \"" + CARD_TYPES_JSON + "\": [\"Card Type\"...]         1-n card types recognized by the payee\n" +
       "//     \"" + PAYMENT_REQUEST_JSON + "\":                     The actual request\n" +
       "//       {\n" +
       "//         \"" + AMOUNT_JSON + "\": nnnn                    Integer of the sum to pay multiplied by 100\n" +
       "//         \"" + CURRENCY_JSON + "\": \"XYZ\"                 Currency in ISO notation\n" +
       "//         \"" + REFERENCE_ID_JSON + "\": \"String\"           Payee reference to order\n" +
       "//         \"" + DATE_TIME_JSON + "\": \"YY-MM-DDThh:mm:ssZ\"  ISO time of request\n" +
       "//         \"" + COMMON_NAME_JSON + "\": \"Name\"              Common name of requester\n" +
       "//         \"" + JSONSignatureDecoder.SIGNATURE_JSON + "\": {}                   Signature object\n" +
       "//       }\n" +
       "//   }\n" +
       "//\n" +
       "function processInvoke() {\n" +
       "    var payee_card_types = getJSONProperty('" + CARD_TYPES_JSON + "');\n" +
       "    json_request = getJSONProperty('" + PAYMENT_REQUEST_JSON + "');\n" +
       "    caller_common_name = getJSONProperty('" + COMMON_NAME_JSON + "');\n" +
       "    request_amount = getJSONProperty('" + AMOUNT_JSON + "');\n" +
       "    var iso_currency = getJSONProperty('" + CURRENCY_JSON + "');\n" +
       "    for (var i = 0; i < currency_list.length; i++) {\n" +
       "        if (currency_list[i].iso_name == iso_currency) {\n"+
       "            request_currency = currency_list[i];\n" +
       "            break;\n" +
       "        }\n" +
       "    }\n" +
       "    if (!request_currency) {\n" +
       "        error('Unrecognized currency: ' + iso_currency);\n" +
       "    }\n" +
       "    request_date_time = getJSONProperty('" + DATE_TIME_JSON + "');\n" +
       "    request_reference_id = getJSONProperty('" + REFERENCE_ID_JSON + "');\n" +
       "    if (aborted_operation) return;\n" +
       "    // Perform the card compatibility/discovery processes\n" +
       "    var count = 0;\n" +
       "    for (var q = 0; q < payee_card_types.length; q++) {\n" +
       "        for (var i = 0; i < card_list.length; i++) {\n" +
       "            if (payee_card_types[q] == card_list[i].type) {\n" +
       "                console.debug('Compatible Card: \"' + payee_card_types[q] + '\"');\n" + 
       "                card_list[i].matching = true;\n" +
       "                count++;\n" +
       "            }\n" +
       "        }\n" +
       "    }\n" +
       "    document.getElementById('content').style.height = (" + (PAYMENT_WINDOW_HEIGHT + 2) +
                    " - document.getElementById('control').offsetHeight - document.getElementById('border').offsetHeight - document.getElementById('activity').offsetHeight) + 'px';\n" +
       "    var button_width = document.getElementById('cancel').offsetWidth;\n" +
       "    document.getElementById('ok').style.width = button_width + 'px';\n" +
       "    document.getElementById('cancel').style.left = ((" +
            PAYMENT_WINDOW_WIDTH + " - button_width) / 2) + 'px';\n" +
       "    document.getElementById('cancel').title = 'Cancel and return to \"' + caller_common_name + '\"';\n" +
       "    document.getElementById('cancel').style.visibility = 'visible';\n" +
       "    if (!count) {\n" +
       "        error('No matching payment cards found, click \"Cancel\" to return to \"' + caller_common_name + '\".');\n" +
       "        return;\n" +
       "    }\n" +

//    Uncomment+
//       "    for (var q = 0; q < card_list.length; q++) {\n" +
//       "        if (card_list[q].matching) {\n"+
//       "            console.debug('Matching card: ' + card_list[q].type);\n" +
//       "        }\n" +
//       "    }\n" +
//    Uncomment-

       "    if (count == 1) {\n" +
       "        // Shortcut: If there is only one matching card we\n" +
       "        // might as well go to the payment display directly.\n" +
       "        for (var q = 0; q < card_list.length; q++) {\n" +
       "            if (card_list[q].matching) {\n"+
       "                displayPaymentRequest(q);\n" +
       "                return;\n" +
       "            }\n" +
       "        }\n" +
       "    } else {\n" +
       "        displayCompatibleCards(count);\n" +
       "    }\n" +
       "}\n\n" +
       "//\n" +
       "// The payment application always query the payee for data.\n" +
       "// There is a timeout associated with the (currently only) request.\n" +
       "//\n" +
       "window.addEventListener('message', function(event) {\n" +
        "    console.debug(event.origin + ' => PaymentAppFrame:\\n' + event.data);\n" +
        "    if (aborted_operation) return;\n" +
        "    if (timeouter_handle) {\n" +
        "        clearTimeout(timeouter_handle);\n" +
        "        timeouter_handle = null;\n" +
        "        json_request = JSON.parse(event.data);\n" +
        "        if (getJSONProperty('" + JSONDecoderCache.CONTEXT_JSON + "') == '" + WCPP_DEMO_CONTEXT_URI + "' && " +
                 "getJSONProperty('" + JSONDecoderCache.QUALIFIER_JSON + "') == '" + Messages.INVOKE + "') {\n" +
        "            document.getElementById('busy').style.visibility = 'hidden';\n" +
        "            processInvoke();\n" +
        "            return;\n" +
        "        }\n" +
        "    }\n" +
        "    error('Unexpected message: ' + event.origin + ' ' + event.data);\n" +
        "}, false);\n\n" +
        "//\n" +
        "// When the payment module IFRAME has been loaded (by the payee),\n" +
        "// the payment process is automatically invoked by the body.onload().\n" +
        "//\n" +
        "function initPaymentApplication() {\n" +
        "    caller_domain = getDomainName(window.document.referrer);\n" +
        "    document.getElementById('border').innerHTML += ' [' + caller_domain + ']';\n" +
        "    if (checkNoErrors()) {\n" +
        "        console.debug('Init Payment Application');\n" +
        "        checkTiming(" + PAYMENT_TIMEOUT_INIT + ");\n" +
        "        window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" + 
                 Messages.INITIALIZE +
                 "')), window.document.referrer);\n" +
        "    }\n" +
        "}\n" +
        "</script>" +
        "</head><body onload=\"initPaymentApplication()\">" +
        "<div id=\"border\" style=\"font-family:" + FONT_VERDANA + ";padding:" + (PAYMENT_DIV_VERTICAL_PADDING - 1) + "px " +
        PAYMENT_DIV_HORIZONTAL_PADDING + "px " + PAYMENT_DIV_VERTICAL_PADDING + "px " +
        PAYMENT_DIV_HORIZONTAL_PADDING + "px;" +
        "color:white;background:" +
        PAYMENT_BORDER_COLOR + ";width:" +
        (PAYMENT_WINDOW_WIDTH - (PAYMENT_DIV_HORIZONTAL_PADDING * 2)) +"px\">Payment Request</div>" +
        "<div id=\"activity\" style=\"padding:" + PAYMENT_DIV_VERTICAL_PADDING + "px " + 
        PAYMENT_DIV_HORIZONTAL_PADDING + "px " + PAYMENT_DIV_VERTICAL_PADDING + "px " + 
        PAYMENT_DIV_HORIZONTAL_PADDING + "px\">" +
        "Initializing...</div>" +
        "<div id=\"content\" style=\"overflow-y:auto;\"></div>" +
        "<div id=\"control\" style=\"z-index:3;position:absolute;bottom:0px;width:" + PAYMENT_WINDOW_WIDTH +"px;padding-top:5px;padding-bottom:10pt\">" +
        "<input id=\"cancel\" type=\"button\" value=\"&nbsp;Cancel&nbsp;\" class=\"stdbtn\" onclick=\"userAbort()\">" +
        "<input id=\"ok\" type=\"button\" value=\"OK\" class=\"stdbtn\" title=\"Authorize Payment!\" onclick=\"userAuthorize()\"></div>" +
        "<img id=\"busy\" src=\"" + PaymentDemoService.working_data_uri + "\" alt=\"html5 requirement...\" style=\"position:absolute;top:" + 
        ((PAYMENT_WINDOW_HEIGHT - PAYMENT_LOADING_SIZE) / 2) + "px;left:" + 
        ((PAYMENT_WINDOW_WIDTH - PAYMENT_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<div id=\"pinerror\" onclick=\"closePINError()\" title=\"Click to close\" " +
        "style=\"line-height:14pt;cursor:pointer;border-width:1px;border-style:solid;border-color:" + 
        PAYMENT_BORDER_COLOR + ";text-align:center;font-family:" + FONT_ARIAL+ ";z-index:3;background:white;position:absolute;visibility:hidden;padding:10pt 20pt 10pt 20pt;" +
        "background-image:url('" + PaymentDemoService.cross_data_uri + "');background-repeat:no-repeat;background-position:top left\">" +
         "</div></body></html>");
        HTML.output (response, s.toString());
      }

    private static StringBuffer productEntry (StringBuffer temp_string, ProductEntry product_entry, String sku, SavedShoppingCart saved_shopping_cart, int index)
      {
        int units = saved_shopping_cart.items.containsKey (sku) ? saved_shopping_cart.items.get (sku): 0;
        StringBuffer s = new StringBuffer (
            "<tr style=\"text-align:center\"><td><img src=\"images/")
        .append (product_entry.image_url)
        .append ("\"></td><td>")
        .append (product_entry.name)
        .append ("</td><td style=\"text-align:right\">")
        .append (price  (product_entry.price_mult_100))
        .append (
            "</td><td><form>" +
            "<table style=\"border-width:0px;padding:0px;margin:0px;border-spacing:2px;border-collapse:separate\">" +
            "<tr>" +
               "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" class=\"updnbtn\" value=\"&#x25b2;\" title=\"More\" onclick=\"updateUnits(this.form.p")
        .append (index)
        .append (", 1, ")
        .append (index)
        .append (")\"></td>" +
            "</tr>" +
            "<tr>" +
               "<td style=\"border-width:0px;padding:0px;margin:0px\"><input size=\"6\" type=\"text\" name=\"p")
        .append (index)
        .append ("\" value=\"")
        .append (units)
        .append ("\" class=\"quantity\" " +
                           "oninput=\"updateInput(")
        .append (index)
        .append (", this);\" autocomplete=\"off\"/></td>" +
                 "</tr>" +
                 "<tr>" +
                    "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" class=\"updnbtn\" value=\"&#x25bc;\" title=\"Less\" onclick=\"updateUnits(this.form.p")
         .append (index)
         .append (", -1, ")
         .append (index)
         .append (")\"></td>" +
                       "</tr>" +
                       "</table></form></td></tr>");
        temp_string.insert (0, "shopping_cart[" + index + "] = new webpki.ShopEntry(" 
                       + product_entry.price_mult_100 + ",'" + product_entry.name + "','" + sku + "'," + units + ");\n");        
        return s;
      }

    private static String price (int price_mult_100) 
      {
        return "$&#x200a;" + String.valueOf (price_mult_100 / 100) + "." + String.valueOf ((price_mult_100 % 100) / 10) + String.valueOf (price_mult_100 % 10);
      }
    
    public static void merchantPage (HttpServletResponse response, SavedShoppingCart saved_shopping_cart) throws IOException, ServletException
      {
        StringBuffer temp_string = new StringBuffer (
            "\nfunction checkOut() {\n" +
            "    if (getTotal()) {\n" +
            "        document.getElementById('shoppingcart').value = JSON.stringify(shopping_cart);\n" +
            "        document.forms.shoot.submit();\n" +           
            "    } else {\n" +
            "        document.getElementById('emptybasket').style.top = ((window.innerHeight - document.getElementById('emptybasket').offsetHeight) / 2) + 'px';\n" +
            "        document.getElementById('emptybasket').style.left = ((window.innerWidth - document.getElementById('emptybasket').offsetWidth) / 2) + 'px';\n" +
            "        document.getElementById('emptybasket').style.visibility = 'visible';\n" +
            "        setTimeout(function() {\n" +
            "            document.getElementById('emptybasket').style.visibility = 'hidden';\n" +
            "        }, 1000);\n" +
            "    }\n" +
            "}\n\n" +
            "function getTotal() {\n" +
            "    var total = 0;\n" +
            "    for (var i = 0; i < shopping_cart.length; i++) {\n" +
            "        total += shopping_cart[i].price_mult_100 * shopping_cart[i].units;\n" +
            "    }\n" +
            "    return total;\n"+
            "}\n\n" +
            "function getPriceString() {\n" +
            "    var price_mult_100 = getTotal();\n" +
            "    return '"+ Currencies.USD.symbol + "' +  Math.floor(price_mult_100 / 100) + '.' +  Math.floor((price_mult_100 % 100) / 10) +  Math.floor(price_mult_100 % 10);\n" +
            "}\n\n" +
            "function updateTotal() {\n" +
            "    document.getElementById('total').innerHTML = getPriceString();\n" +
            "}\n\n" +
            "function updateInput(index, control) {\n" +
            "    if (!numeric_only.test (control.value)) control.value = '0';\n" +
            "    while (control.value.length > 1 && control.value.charAt(0) == '0') control.value = control.value.substring(1);\n" +
            "    shopping_cart[index].units = parseInt(control.value);\n" +
            "    updateTotal();\n" +
            "}\n\n" +
            "function updateUnits(control, value, index) {\n" +
            "    control.value = parseInt(control.value) + value;\n" +
            "    updateInput(index, control);\n" +
            "}\n");

        StringBuffer page_data = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<table>" +
               "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">" +
               MerchantServlet.COMMON_NAME +
               "<br>&nbsp;</td></tr>" +
               "<tr><td id=\"result\"><table style=\"margin-left:auto;margin-right:auto\" class=\"tftable\">" +
                   "<tr><th>Image</th><th>Description</th><th>Price</th><th>Units</th></tr>");
        int q = 0;
        for (String sku : MerchantServlet.products.keySet ())
          {
            page_data.append (productEntry (temp_string, MerchantServlet.products.get (sku), sku, saved_shopping_cart, q++));
          }
        page_data.append (
               "</table></tr></td><tr><td style=\"padding-top:10pt\"><table style=\"margin-left:auto;margin-right:auto\" class=\"tftable\"><tr><th style=\"text-align:center\">Amount to Pay</th><td style=\"text-align:right\" id=\"total\">")
                 .append (price (saved_shopping_cart.total))
                 .append ("</td></tr>" +
                          "</table></td></tr>" +
                          "<tr><td style=\"text-align:center;padding-top:10pt\" id=\"pay\"><input class=\"stdbtn\" type=\"button\" value=\"Checkout..\" title=\"Paying time has come...\" onclick=\"checkOut()\"></td></tr>" +
                          "</table>" +
                          "<form name=\"shoot\" method=\"POST\" action=\"checkout\">" +
                          "<input type=\"hidden\" name=\"shoppingcart\" id=\"shoppingcart\">" +
                          "</form></td></tr>");
         temp_string.insert (0,
                "\n\n\"use strict\";\n\n" +
                "var numeric_only = new RegExp('^[0-9]{1,6}$');\n\n" +
                "var webpki = {};\n\n" +
                "webpki.ShopEntry = function(price_mult_100, name,sku, units) {\n" +
                "    this.price_mult_100 = price_mult_100;\n" +
                "    this.name = name;\n" +
                "    this.sku = sku;\n" +
                "    this.units = units;\n" +
                "};\n\n" +
                "var shopping_cart = [];\n");

        HTML.output (response, HTML.getHTML (temp_string.toString(), 
                                             "><div id=\"emptybasket\" style=\"border-color:grey;border-style:solid;border-width:3px;text-align:center;font-family:" + FONT_ARIAL+ ";z-index:3;background:#f0f0f0;position:absolute;visibility:hidden;padding:5pt 10pt 5pt 10pt\">Nothing ordered yet...</div",
                                             page_data.toString()));
      }

    private static String formatPAN (String pan)
      {
        StringBuffer new_pan = new StringBuffer ();
        for (int i = 0; i < pan.length (); i++)
          {
            if (i != 0 && ((i % 4) == 0))
              {
                new_pan.append (' ');
              }
            new_pan.append (pan.charAt (i));
          }
        return new_pan.toString ();
      }
    
    public static void initCards (HttpServletResponse response, HttpServletRequest request, Vector<CardEntry> card_entries) throws IOException, ServletException 
      {
        StringBuffer s = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">" +
            "<table cellpadding=\"0\" cellspacing=\"0\"><tr><td></td><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Your Payment Cards<br>&nbsp;</td></tr>" +
            "<tr><td colspan=\"2\"><table style=\"margin-bottom:10pt;margin-left:auto;margin-right:auto\">" +
            "<tr><td style=\"font-size:10pt\">Name</td><td><input size=\"18\" type=\"text\" " +
            "title=\"The name will be written on your cards\" maxlength=\"35\" placeholder=\"Name on the card\" name=\"" + CardEntry.USER_FIELD + "\" value=\"")
        .append (card_entries.firstElement ().user == null ? "" : encode (card_entries.firstElement ().user))
        .append ("\"></td></tr>" +
            "<tr><td style=\"font-size:10pt\">PIN</td><td><input size=\"18\" type=\"text\" maxlength=\"" +
            PIN_MAX_LENGTH + "\" " +
            "title=\"This is a DEMO so we don't complicate things :-)\" placeholder=\"Default: " + 
            CardEntry.DEFAULT_PIN + "\" name=\"" + 
            CardEntry.PIN_FIELD + "\" value=\"")
        .append (card_entries.firstElement ().pin == null ? "" : encode (card_entries.firstElement ().pin))
        .append ("\"></td></tr></table></td></tr>");
        for (CardEntry card_entry : card_entries)
          {
            s.append ("<tr><td style=\"text-align:right;padding-right:5pt\"><input type=\"checkbox\" name=\"")
             .append (card_entry.card_type.toString ())
             .append ("\" title=\"Activate/deactivate card\"")
             .append (card_entry.active ? " checked" : "")
             .append ("></td><td>" + CardEntry.CARD_DIV)
             .append (card_entry.base64_image)
             .append ("');\" title=\"This card is")
             .append (MerchantServlet.compatible_with_merchant.contains (card_entry.card_type) ? "" : " NOT")
             .append (" recognized by &quot;" + MerchantServlet.COMMON_NAME + "&quot;\">" +
                      "</div></td></tr><tr><td></td>" +
                      "<td style=\"text-align:center;padding-top:" + PAYMENT_PAN_PADDING_TOP +
                      "px;padding-bottom:" + PAYMENT_PAN_PADDING_BOTTOM + "px\">")
             .append (card_entry.active ? formatPAN (card_entry.pan) : "<i>Inactive Card</i>")
             .append ("</td></tr>");
          }  
        HTML.output (response, HTML.getHTML (null, null, s.append (
            "<tr><td></td><td style=\"text-align:center\"><input type=\"submit\" value=\"Save Changes\" title=\"Cards only &quot;live&quot; in a web session\"></td></tr>" +
            "</table></form></td></tr>").toString ()));
      }

    public static void checkoutPage (HttpServletResponse response, SavedShoppingCart saved_shopping_cart, String invoke_json) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer (
        "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
        "<table>" +
           "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Current Order<br>&nbsp;</td></tr>" +
           "<tr><td id=\"result\"><table style=\"margin-left:auto;margin-right:auto\" class=\"tftable\">" +
               "<tr><th>Description</th><th>Price</th><th>Units</th></tr>");
        for (String sku : saved_shopping_cart.items.keySet ())
          {
            ProductEntry product_entry = MerchantServlet.products.get (sku);
            s.append ("<tr style=\"text-align:center\"><td>")
             .append (product_entry.name)
             .append ("</td><td style=\"text-align:right\">")
             .append (price (product_entry.price_mult_100))
             .append ("</td><td>")
             .append (saved_shopping_cart.items.get (sku).intValue ())
             .append ("</td></tr>");                
          }
        s.append (
            "</table></td></tr><tr><td style=\"padding-top:10pt\"><table style=\"margin-left:auto;margin-right:auto\" class=\"tftable\"><tr><th style=\"text-align:center\">Amount to Pay</th><td style=\"text-align:right\" id=\"total\">")
         .append (price (saved_shopping_cart.total))
         .append("</td></tr>" +
                 "</table></td></tr>" +
                 "<tr><td style=\"text-align:center;padding-top:10pt\" id=\"pay\">")
         .append (getIframeHTML ())
         .append ("</td></tr></table>" +
                  "<form name=\"shoot\" method=\"POST\" action=\"authreq\">" +
                  "<input type=\"hidden\" name=\"authreq\" id=\"authreq\">" +
                  "</form>" +
                  "<form name=\"restore\" method=\"POST\" action=\"" + PaymentDemoService.merchant_url + "\">" +
                  "</form></td></tr>");
        
     StringBuffer temp_string = new StringBuffer (
        "\n\n\"use strict\";\n\n" +
        "var message_state = '" + Messages.INITIALIZE + "';\n\n" +
         "window.addEventListener('message', function(event) {\n" +
        "    console.debug (event.origin + ' = > Checkout message:\\n' + event.data);\n" +
        "    var received_json = JSON.parse(event.data);\n" +
        "    if (received_json['" + JSONDecoderCache.CONTEXT_JSON + "'] != '" + WCPP_DEMO_CONTEXT_URI + "') {\n" +
        "        console.debug('UNDECODABLE MESSAGE');\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] == '" + Messages.ABORT + "') {\n" +
        "        document.forms.restore.submit();\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] != message_state) {\n" +
        "        console.debug('STATE ERROR: ' + event.data + '/' + message_state);\n" +
        "        return;\n" +
        "    }\n" +
        "    if (message_state == '" + Messages.INITIALIZE + "') {\n" +
        "        setTimeout(function(){\n" +
        "            event.source.postMessage(" + invoke_json + ", event.origin);\n" +
//      "        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
        "        }, 500); // \"working\" simulation (it is so darn quick...)\n" +
        "        message_state = '" + Messages.AUTHORIZE + "';\n" +
        "    } else {\n" +
        "        document.getElementById('authreq').value = JSON.stringify(received_json);\n" +
        "        setTimeout(function(){\n" +
        "            document.forms.shoot.submit();\n" +
        "        }, 0);\n" +
        "    }\n" +
        "}, false);\n");
        HTML.output (response, HTML.getHTML (temp_string.toString (), null, s.toString ()));
      }

    public static void resultPage (HttpServletResponse response,
                                   String error_message,
                                   PaymentRequest payment_request, 
                                   String card_type,
                                   String reference_pan,
                                   String transaction_request,
                                   String transaction_response) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer ("<tr><td width=\"100%\" align=\"center\" valign=\"middle\">");
        if (error_message == null)
          {
            s.append ("<table>" +
             "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Order Status<br>&nbsp;</td></tr>" +
             "<tr><td style=\"text-align:center;padding-bottom:15pt;font-size:10pt\">Dear customer, your order has been successfully processed!</td></tr>" +
             "<tr><td><table class=\"tftable\"><tr><th>Our Reference</th><th>Amount</th><th>Card Type</th><th>Card Number</th></tr>" +
             "<tr><td style=\"text-align:center\">")
            .append (payment_request.reference_id)
            .append ("</td><td style=\"text-align:center\">")
            .append (price (payment_request.amount))
            .append ("</td><td style=\"text-align:center\">")
            .append (card_type)
            .append ("</td><td style=\"text-align:center\">")
            .append (reference_pan)
            .append ("</td></tr></table></td></tr></table>");
          }
        else
          {
            s.append ("There was a problem with your order: " + error_message);
          }
        HTML.output (response, HTML.getHTML ("function listFinalExchange() {\n" +
                                             "    console.debug('Transaction request:\\n" + transaction_request + "');\n" +
                                             "    console.debug('Transaction result:\\n" + transaction_response + "')" +
                                             "}\n", 
                                             "onload=\"listFinalExchange()\"", 
                                             s.append ("</td></tr>").toString ()));
      }
  }
