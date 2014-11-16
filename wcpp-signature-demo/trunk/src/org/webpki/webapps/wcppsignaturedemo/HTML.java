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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.ExtendedKeyUsages;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

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
                   "<tr><td style=\"text-align:left\">This site contains a demo of what a true WebCrypto++ implementation " +
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

    public static void paymentPage (HttpServletResponse response, HttpServletRequest request) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer (
        "<!DOCTYPE html>"+
        "<html><head><meta charset=\"UTF-8\">"+
        "<style type=\"text/css\">html {overflow:hidden}\n"+
        "body {font-size:10pt;color:#000000;font-family:" + FONT_ARIAL + ";background-color:white;margin:0px;padding:0px}\n" +
        "table {border-collapse: collapse}\n" +
        "td {padding: 0px}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + ";position:relative}\n" +
        "</style></head><body onload=\"initPayment()\">" +
        "<div id=\"border\" style=\"font-family:" + FONT_VERDANA + ";padding:" + SIGNATURE_DIV_VERTICAL_PADDING + "px " +
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px " +
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px;" +
        "color:white;background:" +
        SIGNATURE_BORDER_COLOR + ";width:" +
        (SIGNATURE_WINDOW_WIDTH - (SIGNATURE_DIV_HORIZONTAL_PADDING * 2)) +"px\">Payment Request</div>" +
        "<div id=\"activity\" style=\"padding:" + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px " + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
        SIGNATURE_DIV_HORIZONTAL_PADDING + "px\">" +
        "Initializing...</div>" +
        "<div id=\"content\" style=\"overflow-y:auto;\"></div>" +
        "<div id=\"control\" style=\"z-index:3;position:absolute;bottom:0px;width:" + SIGNATURE_WINDOW_WIDTH +"px;padding-top:5px;padding-bottom:10pt\">" +
        "<input id=\"cancel\" type=\"button\" value=\"&nbsp;Cancel&nbsp;\" class=\"stdbtn\" onclick=\"userAbort()\">" +
        "<input id=\"ok\" type=\"button\" value=\"OK\" class=\"stdbtn\" title=\"Authorize Payment!\" onclick=\"userAuthorize()\"></div>" +
        "<img id=\"busy\" src=\"" + SignatureDemoService.working_data_uri + "\" alt=\"html5 requirement...\" style=\"position:absolute;top:" + 
        ((SIGNATURE_WINDOW_HEIGHT - SIGNATURE_LOADING_SIZE) / 2) + "px;left:" + 
        ((SIGNATURE_WINDOW_WIDTH - SIGNATURE_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<div id=\"pinerror\" onclick=\"closePINError()\" title=\"Click to close\" " +
        "style=\"line-height:14pt;cursor:pointer;border-width:1px;border-style:solid;border-color:" + 
        SIGNATURE_BORDER_COLOR + ";text-align:center;font-family:" + FONT_ARIAL+ ";z-index:3;background:white;position:absolute;visibility:hidden;padding:10pt 20pt 10pt 20pt;" +
        "background-image:url('" + SignatureDemoService.cross_data_uri + "');background-repeat:no-repeat;background-position:top left\">" +
         "</div>" +
        "<script type=\"text/javascript\">\n" +
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
/*
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
*/
        s.append ("\nwebpki.CardEntry = function(type, pin, pan, authorization_url, base64_image");
        s.append (", bank_encryption_key, client_cert, client_private_key, cert_data");
        s.append (
        ") {\n" +
        "    this.type = type;\n" +
        "    this.pin = pin;\n" +
        "    this.pan = pan;\n" +
        "    this.authorization_url = authorization_url;\n" +
        "    this.base64_image = base64_image;\n");
            s.append (
                "    this.bank_encryption_key = bank_encryption_key;\n" +
                "    this.client_cert_path = [];\n" +
                "    this.client_cert_path.push(client_cert);\n" +
                "    this.client_private_key = client_private_key;\n" +
                "    this.cert_data = cert_data;\n");
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
/*
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
*/
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
        "    console.debug ('Error: ' + message);\n" +
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
        "   if (aborted_operation || window.self.innerWidth != " + SIGNATURE_WINDOW_WIDTH + " || window.self.innerHeight != " + SIGNATURE_WINDOW_HEIGHT + ") {\n" +
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
 //            javaScript (CardEntry.CARD_DIV) +
             "' + card_list[card_index].base64_image + '\\')' + add_on + '\">" +
             "</div></td>';\n" +
        "}\n\n" +
        "function binaryToBase64URL (binarray) {\n" +
        "    var encoded = new String ();\n" +
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
        "        var c = string.charCodeAt (n);\n" +
        "        if (c < 128) {\n" +
        "            buffer.push (c);\n" +
        "        } else if ((c > 127) && (c < 2048)) {\n" +
        "            buffer.push ((c >> 6) | 0xC0);\n" +
        "            buffer.push ((c & 0x3F) | 0x80);\n" +
        "        } else {\n" +
        "            buffer.push ((c >> 12) | 0xE0);\n" +
        "            buffer.push (((c >> 6) & 0x3F) | 0x80);\n" +
        "            buffer.push ((c & 0x3F) | 0x80);\n" +
        "        }\n" +
        "    }\n" +
        "    return new Uint8Array (buffer);\n" +
        "}\n\n" +
        "//\n" +
        "// Although PANs (card numbers) are not really needed from the user's\n" +
        "// point of view, they represent a legacy which should not be ignored...\n" +
        "//\n" +
        "function outputPAN(card_index) {\n" +
        "    var pan_html = '<td style=\"padding-top:" + SIGNATURE_PAN_PADDING_TOP +
             "px;padding-bottom:" + SIGNATURE_PAN_PADDING_BOTTOM + "px;font-size:8pt;font-family:" + javaScript (FONT_VERDANA) + ";text-align:center\">';\n" +
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
        "    document.getElementById('cancel').style.left = '" + SIGNATURE_BUTTON_HORIZ_MARGIN + "px';\n" +
        "    document.getElementById('content').innerHTML = payment_details + cardTableHeader('" +
             SIGNATURE_CARD_RIGHT_MARGIN + "px', " +
             SIGNATURE_CARD_TOP_POSITION + ") + " +
             "'<tr>' + outputCard(card_index, '\" title=\"Don\\'t leave home without it!') + '</tr>" +
             "<tr>' + outputPAN(card_index) + '</tr></table>';\n" +
        "    document.getElementById('details').style.top = (" +
             SIGNATURE_WINDOW_HEIGHT + 
             " - document.getElementById('details').offsetHeight)/2 + 'px';\n" +
//        "    var details_left = (" + (SIGNATURE_WINDOW_WIDTH - CardEntry.CARD_WIDTH - SIGNATURE_CARD_RIGHT_MARGIN) +
             " - document.getElementById('details').offsetWidth) / 2;\n" +
             "    document.getElementById('details').style.left = details_left + 'px';\n" +
             "    document.getElementById('ok').style.left = ((details_left + " +
                 "document.getElementById('pin').offsetLeft - " +
                 "document.getElementById('cancel').offsetWidth) * 2 + " +
                 "document.getElementById('pin').offsetWidth - " +
                 SIGNATURE_BUTTON_HORIZ_MARGIN + ") + 'px';\n" +
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
        "    var cards = cardTableHeader('auto', count < 3 ? " + SIGNATURE_CARD_TOP_POSITION + " : 0);\n" +
        "    for (var q = 0; q < card_list.length; q++) {\n" +
        "        if (card_list[q].matching) {\n"+
        "            cards += left_card ? '<tr>' : '<td style=\"width:" + SIGNATURE_CARD_HORIZ_GUTTER + "px\"></td>';\n" +
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
       "    window.parent.postMessage(JSON.stringify(createJSONBaseCommand ('" +
            Messages.ABORT + "')), window.document.referrer);\n" +
       "}\n\n");
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
       s.append (
       "//\n" +
       "// This is the final part of the user authorization\n" +
       "//\n" +
       "function encryptAndSend(signed_auth_data) {\n" +
       "    authorize_command = createJSONBaseCommand ('" + Messages.SIGNATURE_RESPONSE + "');\n" +
       "    authorize_command." + AUTH_URL_JSON + " = selected_card.authorization_url;\n" +
       "    encrypted_data = authorize_command." + AUTH_DATA_JSON + " = {};\n" +
       "    encrypted_data = encrypted_data." + ENCRYPTED_DATA_JSON + " = {};\n");
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
       "        date_time = date_time.substring (0, date_time.indexOf('.')) + 'Z';\n" +
       "    }\n" +
       "    auth_data." + DATE_TIME_JSON + " = date_time;\n");
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
           s.append (
             "    crypto.subtle.importKey('jwk', selected_card.client_private_key, key_import_alg, false, ['sign']).then (function(private_key) {\n" +
             "    crypto.subtle.sign (key_sign_alg, private_key, convertStringToUTF8(JSON.stringify(auth_data))).then (function(signature) {\n" +
             "        signature_object." + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + " = binaryToBase64URL(new Uint8Array(signature));\n" +
             "        var json_auth_data = JSON.stringify(auth_data);\n" +
             "        console.debug('Unencrypted user authorization:\\n' + json_auth_data);\n" + 
             "        encryptAndSend (convertStringToUTF8(json_auth_data));\n" +
             "    }).then (undefined, function() {error('Failed signing')});\n" +
             "    }).then (undefined, function() {error('Failed importing private key')});\n");
       s.append (
       "}\n\n" +
       "//\n" +
       "// Processes payee's JSON response to the \"" + Messages.INIIALIZE + "\" message.\n");
       s.append (
       "//\n" +
       "// Message syntax:\n" +
       "//   {\n" +
       "//     \"" + JSONDecoderCache.CONTEXT_JSON + "\": \"" + WCPP_DEMO_CONTEXT_URI + "\"\n" +
       "//     \"" + JSONDecoderCache.QUALIFIER_JSON + "\": \"" + Messages.SIGNATURE_REQUEST + "\"\n" +
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
       "    document.getElementById('content').style.height = (" + (SIGNATURE_WINDOW_HEIGHT + 2) +
                    " - document.getElementById('control').offsetHeight - document.getElementById('border').offsetHeight - document.getElementById('activity').offsetHeight) + 'px';\n" +
       "    var button_width = document.getElementById('cancel').offsetWidth;\n" +
       "    document.getElementById('ok').style.width = button_width + 'px';\n" +
       "    document.getElementById('cancel').style.left = ((" +
            SIGNATURE_WINDOW_WIDTH + " - button_width) / 2) + 'px';\n" +
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
        "function receivePayeeResponse(event) {\n" +
        "    console.debug(event.origin + ' => PaymentAppFrame:\\n' + event.data);\n" +
        "    if (aborted_operation) return;\n" +
        "    if (timeouter_handle) {\n" +
        "        clearTimeout(timeouter_handle);\n" +
        "        timeouter_handle = null;\n" +
        "        json_request = JSON.parse(event.data);\n" +
        "        if (getJSONProperty('" + JSONDecoderCache.CONTEXT_JSON + "') == '" + WCPP_DEMO_CONTEXT_URI + "' && " +
                 "getJSONProperty('" + JSONDecoderCache.QUALIFIER_JSON + "') == '" + Messages.SIGNATURE_REQUEST + "') {\n" +
        "            document.getElementById('busy').style.visibility = 'hidden';\n" +
        "            processInvoke();\n" +
        "            return;\n" +
        "        }\n" +
        "    }\n" +
        "    error('Unexpected message: ' + event.origin + ' ' + event.data);\n" +
        "}\n\n" +
        "//\n" +
        "// When the payment module IFRAME has been loaded (by the payee),\n" +
        "// the payment process is automatically invoked by the body.onload().\n" +
        "//\n" +
        "function initPayment() {\n" +
        "    caller_domain = getDomainName(window.document.referrer);\n" +
        "    document.getElementById('border').innerHTML += ' [' + caller_domain + ']';\n" +
        "    if (checkNoErrors()) {\n" +
        "        window.addEventListener('message', receivePayeeResponse, false);\n" +
        "        console.debug('init payment window');\n" +
        "        checkTiming(" + SIGNATURE_TIMEOUT_INIT + ");\n" +
        "        window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" + 
                 Messages.INIIALIZE +
                 "')), window.document.referrer);\n" +
        "    }\n" +
        "}\n" +
        "</script>" +
        "</body></html>");
      }


    public static void noWebCryptoPage (HttpServletResponse response) throws IOException, ServletException 
      {
        HTML.output (response, HTML.getHTML (null, null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">Your Browser Doesn't Support WebCrypto :-(</td></tr>"));
      }

    public static String getBinaryArray (boolean html_flag) throws IOException
      {
        return Base64URL.encode (ArrayUtil.getByteArrayFromInputStream (SignatureDemoService.class.getResourceAsStream (
            html_flag ? "blah.html" : "prov.pdf")));
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
        "var timeouter_handle = null;\n" +
        "var request_reference_id;\n" +
        "var request_date_time;\n" +
        "var caller_common_name;\n" +
        "var caller_domain;\n" +
        "var json_request;\n" +
        "var reference_id;\n" +
        "var object_to_sign;\n" +
        "var request_date_time;\n" +
        "var mime_type;\n" +
        "var document_binary;\n" +
        "var signature_response;\n" +
        "var document_data;\n" +
        "var detached_flag;\n" +
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
        "// This part would in a real WebCrypto++ implemenation be replaced by\n" +
        "// the platform key enumeration and attribute methods\n" +
        "var client_private_key = " + SignatureDemoService.client_private_key.getJWK () + ";\n" +
        "var client_cert_path = ['" + SignatureDemoService.client_eecert_b64 + "'];\n" +
        "var client_cert_data = " + SignatureDemoService.client_cert_data + ";\n\n" +
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
/*
       "   if (!card_list.length) {\n" +
       "       error('You appear to have no payment cards at all, please return " +
           "to the <b>Payment&nbsp;Demo&nbsp;Home</b> and get some!  It\\'s free :-)');\n" +
       "       return false;\n" +
       "   }\n" +
*/
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
        "function createSignatureAndSend(key_import_alg, key_signature_alg, jcs_alg) {\n" +
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
        "function openCredentialDialog() {\n" +
        "    closePINDialog();\n" +
        "    document.getElementById('credential').style.visibility = 'visible';\n" +
        "}\n\n" +
        "function closeCredentialDialog() {\n" +
        "    document.getElementById('credential').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function userSign() {\n" +
        "    closeCredentialDialog();\n" +
        "    document.getElementById('sign').disabled = true;\n" +
        "    var pindialog_width = document.getElementById('pindialog').offsetWidth;\n" +
        "    document.getElementById('pincross').style.height = (border_height - 9"
        + ") + 'px';\n" +
        "    document.getElementById('pincross').style.top = '4px';\n" +
        "    document.getElementById('pincross').style.left = (pindialog_width - border_height + 2) + 'px';\n" +
        "    document.getElementById('pindialog').style.top = Math.floor((" + SIGNATURE_WINDOW_HEIGHT + " - document.getElementById('pindialog').offsetHeight) / 2) + 'px';\n" +
        "    document.getElementById('pindialog').style.left = Math.floor((" + SIGNATURE_WINDOW_WIDTH + " - pindialog_width) / 2) + 'px';\n" +
        "    document.getElementById('pindialog').style.visibility = 'visible';\n" +
        "    document.getElementById('pin').focus();\n" +
        "}\n\n" +
        "function closePINDialog() {\n" +
        "    document.getElementById('sign').disabled = false;\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function showPINError(message) {\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "    document.getElementById('pinerror').innerHTML = '<div style=\"padding:8pt 12pt 0pt 12pt;color:red\">' + message + '</div>';\n" +
        "    userSign();\n" +
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
        "        showPINError('Too many PIN errors,<br>the card is blocked!');\n" +
        "        return;\n" +
        "    }\n" +
        "    document.getElementById('pindialog').style.visibility = 'hidden';\n" +
        "    document.getElementById('busy').style.visibility = 'visible';\n" +
        "    signature_response = createJSONBaseCommand('" + Messages.SIGNATURE_RESPONSE + "');\n" +
        "    var request_data = signature_response." + REQUEST_DATA_JSON + " = {};\n" +
        "    request_data." + ORIGIN_JSON + " = window.document.referrer;\n" +
        "    request_data." + REFERENCE_ID_JSON + " = reference_id;\n" +
        "    request_data." + DATE_TIME_JSON + " = request_date_time;\n" +
        "    document_data = signature_response." + DOCUMENT_DATA_JSON + " = {};\n" +
        "    var date_time = new Date().toISOString();\n" +
        "    if (date_time.indexOf('.') > 0 && date_time.indexOf('Z') > 0) {\n" +
        "        date_time = date_time.substring (0, date_time.indexOf('.')) + 'Z';\n" +
        "    }\n" +
        "    signature_response." + DATE_TIME_JSON + " = date_time;\n" +
        "    signature_object = signature_response." + JSONSignatureDecoder.SIGNATURE_JSON + " = {};\n" +
        "    document_data." + MIME_TYPE_JSON + " = mime_type;\n" +
        "    var key_import_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "    var key_signature_alg = {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}};\n" +
        "    var jcs_alg = '" + AsymSignatureAlgorithms.RSA_SHA256.getURI () + "';\n" +
        "    if (client_private_key.kty == 'EC') {\n" +
        "        error('Not implemented yet');\n" +
        "    }\n" +
        "    var document_hash = document_data." + DOCUMENT_HASH_JSON + " = {};\n" +
        "    document_hash." + JSONSignatureDecoder.ALGORITHM_JSON + " = '" + HashAlgorithms.SHA256.getURI () + "';\n" +
        "    crypto.subtle.digest({name: 'SHA-256'}, document_binary).then (function(result) {\n" +
        "        document_hash." + VALUE_JSON + " = binaryToBase64URL(new Uint8Array(result));\n" +
        "        createSignatureAndSend(key_import_alg, key_signature_alg, jcs_alg);\n" +
        "    }).then (undefined, function() {error('Failed hashing document')});\n" +
        "}\n\n" +
        "function processInvoke() {\n" +
        "    object_to_sign = getJSONProperty('" + OBJECT_TO_SIGN_JSON + "');\n" +
        "    if (aborted_operation) return;\n" +
        "    mime_type = object_to_sign." + MIME_TYPE_JSON + ";\n" +
        "    document_binary = decodeBase64URL(object_to_sign." + DOCUMENT_JSON + ");\n" +
        "    reference_id = getJSONProperty('" + REFERENCE_ID_JSON + "');\n" +
        "    request_date_time = getJSONProperty('" + DATE_TIME_JSON + "');\n" +
        "    if (aborted_operation) return;\n" +
        "    detached_flag = getJSONProperty('" + SIGNATURE_TYPE_JSON + "') == '" + SIGNATURE_TYPE_DETACHED + "';\n" +
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
        "    var button_width = document.getElementById('cancel').offsetWidth;\n" +
        "    var button_h_margin = Math.floor(button_width / 3);\n" +
        "    document.getElementById('cancel').style.left =  + button_h_margin + 'px';\n" +
        "    var attention_left = " + SIGNATURE_WINDOW_WIDTH + " - 2 * button_h_margin - button_width - document.getElementById('attention').offsetWidth;\n" +
        "    document.getElementById('attention').style.left = attention_left + 'px';\n" +
        "    document.getElementById('attention').style.top = Math.floor((control_height - attention_height) / 2) + 'px';\n" +
        "    document.getElementById('sign').style.width = button_width + 'px';\n" +
        "    document.getElementById('sign').style.left = (" + SIGNATURE_WINDOW_WIDTH + " - button_h_margin - button_width) + 'px';\n" +
        "    document.getElementById('cancel').style.top = document.getElementById('sign').style.top = (Math.floor((control_height - button_height) / 2)) + 'px';\n" +
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
          "<input id=\"sign\" title=\"Sign document!\" type=\"button\" value=\"Sign...\" class=\"stdbtn\"onclick=\"userSign()\">" +
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
                      "pincross",
                      "Enter a PIN to activate the signature key...", 
                      "Signature PIN",
                      "closePINDialog") +
        "<div id=\"pinerror\"></div>" +
        "<div style=\"text-align:center;padding:8pt 15pt 8pt 15pt\"><input id=\"pin\" " +
             "title=\"Try &quot;1234&quot; :-)\" style=\"font-family:" + FONT_VERDANA + ";padding-left:3px;letter-spacing:2px;background-color:white\" " +
             "type=\"password\" size=\"" + PIN_FIELD_SIZE +
             "\" maxlength=\"" + PIN_MAX_LENGTH + "\"></div>" +
         "<div style=\"text-align:center;padding-bottom:8pt\"><input style=\"font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "\" type=\"button\" value=\"OK\" onclick=\"performSignatureOperation()\"></div>" +
        "</div>" +
        getDialogBox ("credential",
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
            "<div style=\"font-family:" + FONT_VERDANA + ";padding:" + (SIGNATURE_DIV_VERTICAL_PADDING - 1) + "px " + 
            30 + "pt " + SIGNATURE_DIV_VERTICAL_PADDING + "px " + 
            SIGNATURE_DIV_HORIZONTAL_PADDING + "px;" +
            "color:white;background:" +
            SIGNATURE_BORDER_COLOR + "\">" + header_text + "<img src=\"" + SignatureDemoService.cross_data_uri + 
            "\" id=\"" + cross_id + "\" onclick=\"" + close_method + "()\" " +
            "title=\"Click to close\" style=\"cursor:pointer;position:absolute\"></div>";
      }

    public static void signData (HttpServletResponse response, boolean html_flag, boolean json_flag, boolean detached_flag) throws IOException, ServletException 
      {
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
        "        var invoke_object = createJSONBaseCommand('" + 
                 Messages.SIGNATURE_REQUEST +
                 "');\n" +
        "        invoke_object." + REFERENCE_ID_JSON + " = '#" +  (SignatureDemoService.reference_id++) + "';\n" +
        "        invoke_object." + DATE_TIME_JSON + " = '" + ISODateTime.formatDateTime (new Date (), true) + "';\n" +
        "        invoke_object." + SIGNATURE_FORMAT_JSON + " = '" + (json_flag ? SIGNATURE_FORMAT_JCS : SIGNATURE_FORMAT_XML) + "';\n" +
        "        invoke_object." + SIGNATURE_TYPE_JSON + " = '" + (detached_flag ? SIGNATURE_TYPE_DETACHED : SIGNATURE_TYPE_EMBEDDED) + "';\n" +
        "        var object_to_sign = invoke_object." + OBJECT_TO_SIGN_JSON + " = {};\n" +
        "        object_to_sign." + MIME_TYPE_JSON + " = '" + (html_flag ? "text/html" : "application/pdf") + "';\n" +
        "        object_to_sign." + DOCUMENT_JSON + " = '" + getBinaryArray (html_flag) + "';\n" +
        "        setTimeout(function(){\n" +
        "            event.source.postMessage(JSON.stringify(invoke_object), event.origin);\n" +
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
                "<form name=\"shoot\" method=\"POST\" action=\"signedresult\"><input type=\"hidden\" " +
                "name=\"signature\" id=\"signature\"></form></td></tr>"));
      }

    public static void signatureFrame (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, getHTMLSignatureFrameSource ());
      }

    public static void signedResult (HttpServletResponse response, String message, boolean error) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null, null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table><tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Resulting Signature<br>&nbsp;</td></tr><tr><td>" +
                (error ? "<span style=\"font-size:10pt;color:red\">" + encode (message) + "</span>" : 
                  "<div style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;max-width:800pt;padding:10pt;word-wrap:break-word;box-shadow:3pt 3pt 3pt #D0D0D0;\">" +
                  message + "</div>") +
                "</td></tr></table></td></tr>"));
      }

    public static void signatureCommandPage (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null, null,
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table><tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">Select Signature Parameters<br>&nbsp;</td></tr><tr><td>" +
            "<form method=\"POST\" action=\"signcmd\"><table class=\"tftable\">" +
            "<tr><td rowspan=\"2\">Document Type</td>" +
            "<td><input type=\"radio\" name=\"doctype\" checked value=\"html\">&nbsp;HTML</td>" +
            "</tr><tr><td><input type=\"radio\" name=\"doctype\" value=\"pdf\">&nbsp;PDF</td></tr>" +
            "<tr><td rowspan=\"2\">Signature format</td>" +
            "<td><input type=\"radio\" name=\"sigfmt\" checked value=\"jcs\">&nbsp;JSON (JCS)</td></tr>" +
            "<tr><td><input type=\"radio\" name=\"sigfmt\" value=\"xml\">&nbsp;XML DSig</td></tr>" +
            "<tr><td rowspan=\"2\">Signature Type</td>" +
            "<td><input type=\"radio\" name=\"sigtype\" checked value=\"det\">&nbsp;Detached</td></tr>" +
            "<tr><td><input type=\"radio\" name=\"sigtype\" value=\"emb\">&nbsp;Embedding</td></tr>" +
            "<tr><td colspan=\"2\" style=\"text-align:center\"><input type=\"submit\" value=\"Continue..\"></td></tr>" +
            "</table></form>" +
            "</td></tr></table></td></tr>"));
      }
  }
