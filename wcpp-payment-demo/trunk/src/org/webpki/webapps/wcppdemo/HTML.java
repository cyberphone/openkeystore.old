package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
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
        ".tftable {border-collapse:collapse}\n" +
        ".tftable th {font-size:10pt;background:" +
          "linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);" +
          "border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color:#a9a9a9;" +
          "text-align:center;font-family:" + FONT_ARIAL + "}\n" +
        ".tftable tr {background-color:#FFFFE0}\n" +
        ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;font-family:" + FONT_ARIAL + "}\n" +
        "body {font-size:10pt;color:#000000;font-family:" + FONT_VERDANA + ";background-color:white}\n" +
        "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:" + FONT_ARIAL + ";text-decoration:none}\n" +
        "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:" + FONT_ARIAL + ";text-decoration:none}\n" +
        "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:" + FONT_ARIAL + "}\n" +
        "td {font-size:8pt;font-family:" + FONT_VERDANA + "}\n" +
        ".quantity {text-align:right;font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + "}\n" +
        ".updnbtn {vertical-align:middle;text-align:center;font-weight:normal;font-size:8px;font-family:" + FONT_VERDANA + ";margin:0px;border-spacing:0px;padding:2px 3px 2px 3px}\n" +
        ".headline {font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "}\n";
    

    static String getIframeHTML ()
      {
        return "<iframe src=\"" + Init.bank_url +
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
         .append (Init.bank_url)
         .append ("'\" title=\"Back to the bank!\" style=\"cursor:pointer;position:absolute;top:15px;left:15px;z-index:5;visibility:visible;padding:5pt 8pt 5pt 8pt;font-size:12pt;text-align:center;background: radial-gradient(ellipse at center, rgba(255,255,255,1) 0%,rgba(242,243,252,1) 38%,rgba(196,210,242,1) 100%);border-radius:8pt;border-width:1px;border-style:solid;border-color:#B0B0B0;box-shadow:3pt 3pt 3pt #D0D0D0;}\">" +
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

    public static void homePage (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width:600px;\" cellpadding=\"4\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:" + FONT_ARIAL + "\">WebCrypto++ Payment Demo<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">This site contains a demo of what a true WebCrypto++ implementation " +
                   "could offer for <span style=\"color:red\">decentralized payment systems</span>.</td></tr>" +
                   "<tr><td align=\"left\">In particular note the <span style=\"color:red\">automatic payment card discovery</span> process " +
                   "and that <span style=\"color:red\">payment card logotypes are personalized</span> since they "+
                   "are read from the user's local key-store.</td></tr>" +
                   "<tr><td>By applying <span style=\"color:red\">3D Secure</span> like methods and <span style=\"color:red\">EMV tokenization</span>, there is no need for " +
                   "handing over static credit-card information to merchants.</td></tr>" +
                   "<tr><td align=\"left\">Although the demo is a mockup (no &quot;polyfill&quot; in the world can replace WebCrypto++), " +
                   "the IFRAME solution and cross-domain communication using <code>postMessage()</code> should be pretty close to that of a real system.</td></tr>" +
                   "<tr><td align=\"center\"><table cellspacing=\"10\">" +
                   "<tr align=\"left\"><td><a href=\"" + Init.bank_url + "/cards\">Initialize Payment Cards</a></td><td><i>Mandatory</i> First Step</td></tr>" +
                   "<tr align=\"left\"><td><a href=\"" + Init.merchant_url + "\">Go To Merchant</a></td><td>Shop Til You Drop!</td></tr>" +
                   "<tr align=\"left\"><td><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/pki-webcrypto.pdf\">WebCrypto++</a></td><td>The Specification</td></tr>" +
                   "<tr align=\"left\"><td><a target=\"_blank\" href=\"https://code.google.com/p/openkeystore/source/browse/#svn/wcpp-payment-demo\">Source Code</a></td><td>For Nerds...</td></tr>" +
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
        ".stdbtn {font-weight:normal;font-size:10pt;font-family:" + FONT_ARIAL + ";position:relative;visibility:hidden}\n" +
        "</style></head><body onload=\"initPayment()\">" +
        "<div id=\"border\" style=\"font-family:" + FONT_VERDANA + ";padding:" + PAYMENT_DIV_VERTICAL_PADDING + "px " +
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
        "<img id=\"busy\" src=\"" + Init.working_data_uri + "\" alt=\"html5 requirement...\" style=\"position:absolute;top:" + 
        ((PAYMENT_WINDOW_HEIGHT - PAYMENT_LOADING_SIZE) / 2) + "px;left:" + 
        ((PAYMENT_WINDOW_WIDTH - PAYMENT_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<div id=\"pinerror\" onclick=\"closePINError()\" title=\"Click to close\" " +
        "style=\"line-height:14pt;cursor:pointer;border-width:1px;border-style:solid;border-color:" + 
        PAYMENT_BORDER_COLOR + ";text-align:center;font-family:" + FONT_ARIAL+ ";z-index:3;background:white;position:absolute;visibility:hidden;padding:10pt 20pt 10pt 20pt;" +
        "background-image:url('" + Init.cross_data_uri + "');background-repeat:no-repeat;background-position:top left\">" +
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
        s.append ("\nwebpki.CardEntry = function(type, pin, pan, transaction_url, base64_image");
        if (Init.web_crypto)
          {
            s.append (", bank_encryption_key, client_cert, client_private_key, cert_data");
          }
        s.append (
        ") {\n" +
        "    this.type = type;\n" +
        "    this.pin = pin;\n" +
        "    this.pan = pan;\n" +
        "    this.transaction_url = transaction_url;\n" +
        "    this.base64_image = base64_image;\n");
        if (Init.web_crypto)
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
                         .append(card_entry.transaction_url)
                         .append("', '")
                         .append(card_entry.base64_image)
                         .append ("'");
                        if (Init.web_crypto)
                          {
                            s.append (", ");
                            binArray (s, card_entry.bank_encryption_key);
                            s.append (", '")
                             .append (card_entry.client_certificate)
                             .append ("', ");
                            binArray (s, card_entry.client_key);
                            s.append (", ")
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
        "    console.debug ('Error: ' + message);\n" +
        "    if (!aborted_operation) {\n" +
        "        document.getElementById('activity').innerHTML='ABORTED:<br>' + message;\n" +
        "        aborted_operation = true;\n" +
        "    }\n" +
        "    document.getElementById('busy').style.visibility = 'hidden';\n" +
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
        "   timeouter_handle = setTimeout(function () {error('Timeout')}, milliseconds);\n" +
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
        "function binaryToBase64 (binarray) {\n" +
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
       "    window.parent.postMessage(JSON.stringify(createJSONBaseCommand ('" +
            Messages.ABORT + "')), window.document.referrer);\n" +
       "}\n\n" +
       "//\n" +
       "// This is the final part of the user authorization\n" +
       "//\n" +
       "function encryptAndSend (signed_auth_data) {\n" +
       "    var authorize_command = createJSONBaseCommand ('" + Messages.AUTHORIZE + "');\n" +
       "    authorize_command." + AUTH_URL_JSON + " = selected_card.transaction_url;\n" +
       "    var encrypted_data = authorize_command." + AUTH_DATA_JSON + " = {};\n" +
       "    encrypted_data = encrypted_data." + ENCRYPTED_DATA_JSON + " = {};\n");
       if (Init.web_crypto)
         {
           s.append (
             "    var sym_alg = {name: 'AES-CBC', length: 256};\n" +
             "    crypto.subtle.generateKey(sym_alg, true, ['encrypt', 'decrypt']).then (function(aes_key) {\n" +
             "    var enc_alg = {\n" +
             "        name: 'AES-CBC',\n" +
             "        iv: window.crypto.getRandomValues(new Uint8Array(16))\n" +
             "    };\n" +
             "    crypto.subtle.encrypt(enc_alg, aes_key, signed_auth_data).then (function (main_cryptogram) {\n" +
             "    crypto.subtle.exportKey('raw', aes_key).then (function (raw_aes_key) {\n" +
             "    var asym_alg = {name: 'RSA-OAEP', hash: 'SHA-256'};\n" +
             "    crypto.subtle.importKey('spki', selected_card.bank_encryption_key, asym_alg, true, ['encrypt']).then (function (public_key) {\n" +
             "    crypto.subtle.encrypt(asym_alg, public_key, new Uint8Array(raw_aes_key)).then (function (encryped_aes_key) {\n" +
             "    crypto.subtle.exportKey('jwk', public_key).then (function (jwk_key) {\n" +
             "        var encrypted_key = {};\n" +
             "        encrypted_key." + ALGORITHM_JSON + " = '" + AsymEncryptionAlgorithms.RSA_OAEP_SHA256_MGF1P.getURI () + "';\n" +
             "        var public_key = {};\n" +
             "        encrypted_key." + JSONSignatureDecoder.PUBLIC_KEY_JSON + " = public_key;\n" +
             "        var rsa_key = {};\n" +
             "        public_key." + JSONSignatureDecoder.RSA_JSON + " = rsa_key;\n" +
             "        rsa_key." + JSONSignatureDecoder.MODULUS_JSON + " = jwk_key.n;\n" +
             "        rsa_key." + JSONSignatureDecoder.EXPONENT_JSON + " = jwk_key.e;\n" +
             "        encrypted_key." + CIPHER_TEXT_JSON + " = binaryToBase64(new Uint8Array(encryped_aes_key));\n" +
             "        encrypted_data." + ALGORITHM_JSON + " = '" + SymEncryptionAlgorithms.AES_CBC_P5.getURI () + "';\n" +
             "        encrypted_data." + IV_JSON + " = binaryToBase64(enc_alg.iv);\n" +
             "        encrypted_data." + ENCRYPTED_KEY_JSON + " = encrypted_key;\n" +
             "        encrypted_data." + CIPHER_TEXT_JSON + " = binaryToBase64(new Uint8Array(main_cryptogram));\n" +
//             "        encrypted_data.BLAJ = binaryToBase64(new Uint8Array(encryped_aes_key));\n" +
 //            "        encrypted_data.KLAJ = binaryToBase64(new Uint8Array(main_cryptogram));\n" +
             "        window.parent.postMessage(JSON.stringify(authorize_command), window.document.referrer);\n" +
             "    }).then (undefined, function () {error('Failed exporting public key')});\n" +
             "    }).then (undefined, function () {error('Failed encrypting using public key')});\n" +
             "    }).then (undefined, function () {error('Failed import public key')});\n" +
             "    }).then (undefined, function () {error('Failed exporting symmetric key')});\n" +
             "    }).then (undefined, function () {error('Failed encrypting using symmetric key')});\n" +
             "    }).then (undefined, function () {error('Failed generating symmetric key')});\n");
         }
       else
         {
           s.append (
             "    // For a lame GUI-demo base64 is \"encryption\", right?\n" +
             "    encrypted_data." + CIPHER_TEXT_JSON + " = binaryToBase64(signed_auth_data);\n" +
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
       "        date_time = date_time.substring (0, date_time.indexOf('.')) + 'Z';\n" +
       "    }\n" +
       "    auth_data." + DATE_TIME_JSON + " = date_time;\n");
       if (Init.web_crypto)
         {
           s.append (
             "    // Sign \"" + AUTH_DATA_JSON + "\"\n" +
             "    var signature_object = {};\n" +
             "    auth_data." + JSONSignatureDecoder.SIGNATURE_JSON + " = signature_object;\n" +
             "    signature_object." + JSONSignatureDecoder.ALGORITHM_JSON + " = '" + AsymSignatureAlgorithms.RSA_SHA256.getURI () + "';\n" +
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
       if (Init.web_crypto)
         {
           s.append (
             "    var sign_alg = {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'};\n" +
             "    crypto.subtle.importKey('pkcs8', selected_card.client_private_key, sign_alg, true, ['sign']).then (function (private_key) {\n" +
             "    crypto.subtle.sign (sign_alg, private_key, convertStringToUTF8(JSON.stringify(auth_data))).then (function (signature) {\n" +
             "        signature_object." + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + " = binaryToBase64(new Uint8Array(signature));\n" +
             "        var json_auth_data = JSON.stringify(auth_data);\n" +
             "        console.debug('Unencrypted user authorization:\\n' + json_auth_data);\n" + 
             "        encryptAndSend (convertStringToUTF8(json_auth_data));\n" +
             "    }).then (undefined, function () {error('Failed signing')});\n" +
             "    }).then (undefined, function () {error('Failed importing private key')});\n");
         }
       else
         {
           s.append (
             "    var json_auth_data = JSON.stringify(auth_data);\n" +
             "    console.debug('Unencrypted user authorization:\\n' + json_auth_data);\n" + 
             "    encryptAndSend (convertStringToUTF8(json_auth_data));\n");
         }
       s.append (
       "}\n\n" +
       "//\n" +
       "// Processes payee's JSON response to the \"" + Messages.INITIALIZE + "\" message.\n");
       if (!Init.web_crypto)
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
       "//         \"" + JSONSignatureDecoder.SIGNATURE_JSON + "\": \"{}\"                 Signature object\n" +
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
       "// There is a timeout associated the (currently only) request.\n" +
       "//\n" +
        "function receivePayeeResponse(event) {\n" +
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
        "}\n\n" +
        "//\n" +
        "// When the payment module IFRAME has been loaded (by the payee),\n" +
        "// the payment process is automatically invoked by the body.onload().\n" +
        "//\n" +
        "function initPayment() {\n" +
        "    caller_domain = window.document.referrer;\n" +
        "    caller_domain = caller_domain.substring(caller_domain.indexOf('://') + 3);\n" +
        "    if (caller_domain.indexOf(':') > 0) {\n" +
        "        caller_domain = caller_domain.substring(0, caller_domain.indexOf(':'));\n" +
        "    }\n" +
        "    if (caller_domain.indexOf('/') > 0) {\n" +
        "        caller_domain = caller_domain.substring(0, caller_domain.indexOf('/'));\n" +
        "    }\n" +
        "    document.getElementById('border').innerHTML += ' [' + caller_domain + ']';\n" +
        "    if (checkNoErrors()) {\n" +
        "        window.addEventListener('message', receivePayeeResponse, false);\n" +
        "        console.debug('init payment window');\n" +
        "        checkTiming(" + PAYMENT_TIMEOUT_INIT + ");\n" +
        "        window.parent.postMessage(JSON.stringify(createJSONBaseCommand('" + 
                 Messages.INITIALIZE +
                 "')), window.document.referrer);\n" +
        "    }\n" +
        "}\n" +
        "</script>" +
        "</body></html>");
        HTML.output (response, s.toString());
      }

    private static void binArray (StringBuffer s, byte[] bytes)
      {
        s.append ("new Uint8Array([");
        boolean next = false;
        for (byte b : bytes)
          {
            if (next)
              {
                s.append (',');
              }
            s.append (b & 0xFF);
            next = true;
          }
        s.append ("])");
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
            "    if (getTotal()) {\n");
        if (Init.web_crypto)
          {
            temp_string.append (
            "        document.getElementById('shoppingcart').value = JSON.stringify(shopping_cart);\n" +
            "        document.forms.shoot.submit();\n");            
          }
        else
          {
            temp_string.append (
            "        shopping_enabled = false;\n" +
            "        window.addEventListener('message', receivePaymentMessage, false);\n" +
            "        save_checkout_html = document.getElementById('pay').innerHTML;\n" +
            "        document.getElementById('pay').innerHTML = paycode;\n");
          }
        temp_string.append (
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
            "function updateInput(index, control) {\n");
        if (Init.web_crypto)
          {
            temp_string.append (
            "    if (!numeric_only.test (control.value)) control.value = '0';\n" +
            "    while (control.value.length > 1 && control.value.charAt(0) == '0') control.value = control.value.substring(1);\n" +
            "    shopping_cart[index].units = parseInt(control.value);\n" +
            "    updateTotal();\n");
          }
        else
          {
            temp_string.append (
                "    if (shopping_enabled) {\n" +
               "        if (!numeric_only.test (control.value)) control.value = '0';\n" +
               "        while (control.value.length > 1 && control.value.charAt(0) == '0') control.value = control.value.substring(1);\n" +
               "        shopping_cart[index].units = parseInt(control.value);\n" +
               "        updateTotal();\n" +
               "    } else {\n" +
               "        control.value = shopping_cart[index].units;\n" +
               "    }\n");
          }
        temp_string.append (
            "}\n\n" +
            "function updateUnits(control, value, index) {\n" +
            "    control.value = parseInt(control.value) + value;\n" +
            "    updateInput(index, control);\n" +
            "}\n");
        if (!Init.web_crypto)
          {
            temp_string.append (
            "\n" +
            "function createJSONBaseCommand(command_property_value) {\n" +
            "    var json = {};\n" +
            "    json['" + JSONDecoderCache.CONTEXT_JSON + "'] = '" + WCPP_DEMO_CONTEXT_URI + "';\n" +
            "    json['" + JSONDecoderCache.QUALIFIER_JSON + "'] = command_property_value;\n" +
            "    return json;\n" +
            "}\n\n" +
            "function receivePaymentMessage(event) {\n" +
            "    console.debug (event.origin + ' => MerchantApp:\\n' + event.data);\n" +
            "    var received_json = JSON.parse(event.data);\n" +
            "    if (received_json['" + JSONDecoderCache.CONTEXT_JSON + "'] != '" + WCPP_DEMO_CONTEXT_URI + "') {\n" +
            "        console.debug('MESSAGE ERROR: ' + event.data);\n" +
            "        payment_status = 'Failed***';\n" +
            "        return;\n" +
            "    }\n" +
            "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] == '" + Messages.ABORT + "') {\n" +
            "        document.getElementById('pay').innerHTML = save_checkout_html;\n" +
            "        payment_status = '" + Messages.INITIALIZE + "';\n" +
            "        shopping_enabled = true;\n" +
            "        return;\n" +
            "    }\n" +
            "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] != payment_status) {\n" +
            "        console.debug('STATE ERROR: ' + event.data + '/' + payment_status);\n" +
            "        payment_status = 'Failed***';\n" +
            "        return;\n" +
            "    }\n" +
            "    if (payment_status == '" + Messages.INITIALIZE + "') {\n" +
            "        setTimeout(function(){\n" +
            "        var returned_json = createJSONBaseCommand('" + Messages.INVOKE + "');\n" +
            "        var inner_json = returned_json." + PAYMENT_REQUEST_JSON + " = {}\n" +
            "        inner_json." + COMMON_NAME_JSON + " = '" + MerchantServlet.COMMON_NAME + "';\n" +
            "        inner_json." + CURRENCY_JSON + " = 'USD';\n" +
            "        inner_json." + AMOUNT_JSON + " = getTotal();\n" +
            "        inner_json." + REFERENCE_ID_JSON + " = '#' + next_reference_id++;\n" +
            "        var date_time = new Date().toISOString();\n" +
            "        if (date_time.indexOf('.') > 0 && date_time.indexOf('Z') > 0) {\n" +
            "            date_time = date_time.substring (0, date_time.indexOf('.')) + 'Z';\n" +
            "        }\n" +
            "        inner_json." + DATE_TIME_JSON + " = date_time;\n" +
            "        returned_json." + CARD_TYPES_JSON + " = [];\n" +
            "        returned_json." + CARD_TYPES_JSON + ".push('NeverHeardOfCard');\n");
            for (CardTypes card_type : MerchantServlet.compatible_with_merchant)
              {
                temp_string.append ("        returned_json." + CARD_TYPES_JSON + ".push('")
                           .append (card_type.toString())
                           .append ("');\n");
              }
            temp_string.append (
            "        event.source.postMessage(JSON.stringify(returned_json), event.origin);\n" +
//          "        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
            "        }, 500);\n" +
            "        payment_status = '" + Messages.AUTHORIZE + "';\n" +
            "    }\n" +
            "    else if (payment_status == '" + Messages.AUTHORIZE + "') {\n" +
            "        setTimeout(function(){\n" +
            "        var url = received_json." + AUTH_URL_JSON + ";\n" +
            "        if (!url) alert('failed-URL');\n" +
            "        transaction_channel.open('POST', url, true);\n" +
            "        transaction_channel.setRequestHeader('Content-Type', 'application/json');\n" +
            "        transaction_channel.onreadystatechange = function () {\n" +
            "            if (transaction_channel.readyState == 4) {\n" +
            "                if (transaction_channel.status == 200) {\n" +
            "                    var json_transaction = JSON.parse(transaction_channel.responseText);\n" +
            "                    console.debug('Transaction response:\\n' + JSON.stringify(json_transaction));\n" +
            "                    if (json_transaction." + ERROR_JSON + ") {\n" +
            "                        document.getElementById('result').innerHTML = 'Errors Occured: ' + json_transaction." + ERROR_JSON + ";\n" +
            "                    } else {\n" +
            "                        document.getElementById('result').innerHTML = '<table>" +
            "<tr><td style=\"padding-bottom:8pt\">Dear customer, your order has been successfully processed!</td></tr>" +
            "<tr><td>Amount: ' + getPriceString() + '</td></tr>" +
            "<tr><td>' + json_transaction." + CARD_TYPE_JSON + 
            " + ': ' + json_transaction." + REFERENCE_PAN_JSON + " + '</td></tr>" +
            "</table>';\n" +
            "                    }\n" +
            "                } else {\n" +
            "                    document.getElementById('result').innerHTML = 'Errors Occured ' + transaction_channel.readyState + ' status is ' + transaction_channel.status;\n" +
            "                }\n" +
            "                document.getElementById('pay').innerHTML = '';\n" +
            "            } else {\n" +
            "                console.debug('XHR state: ' + transaction_channel.readyState);\n" +
            "            }\n" +
            "        }\n" +
            "        var transaction_request = createJSONBaseCommand('" + Messages.TRANSACTION_REQUEST + "');\n" +
            "        transaction_request." + AUTH_DATA_JSON + " = received_json." + AUTH_DATA_JSON + ";\n" +
            "        transaction_request." + CLIENT_IP_ADDRESS_JSON + " = '220.67.0.19';\n" +
            "        transaction_request." + TRANSACTION_ID_JSON + " = '#4545445';\n" +
            "        var date_time = new Date().toISOString();\n" +
            "        if (date_time.indexOf('.') > 0 && date_time.indexOf('Z') > 0) {\n" +
            "            date_time = date_time.substring (0, date_time.indexOf('.')) + 'Z';\n" +
            "        }\n" +
            "        transaction_request." + DATE_TIME_JSON + " = date_time;\n" +
            "        transaction_channel.send(JSON.stringify(transaction_request));\n" +
            "        }, 1500);\n" +
            "    }\n" +
            "}\n");
          }

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
               "<tr><td style=\"border-width:1px 1px 0px 0px;background:white\"></td><td style=\"text-align:center\">Total Amount</td><td style=\"text-align:right\" id=\"total\">")
                 .append (price (saved_shopping_cart.total))
                 .append ("</td><td style=\"border-width:1px 0px 0px 1px;background:white\"></td></tr>" +
           "</table></td></tr>" +
           "<tr><td style=\"text-align:center;padding-top:10pt\" id=\"pay\"><input class=\"stdbtn\" type=\"button\" value=\"Checkout..\" title=\"Paying time has come...\" onclick=\"checkOut()\"></td></tr>" +
         "</table></td></tr>");
        if (Init.web_crypto)
          {
            page_data.append ("<form name=\"shoot\" method=\"POST\" action=\"checkout\">" +
                              "<input type=\"hidden\" name=\"shoppingcart\" id=\"shoppingcart\">" +
                              "</form>");
          }
        temp_string.insert (0,
                "\n\n\"use strict\";\n\n" +
                 "var numeric_only = new RegExp('^[0-9]{1,6}$');\n\n" +
                (Init.web_crypto ? "" :
                  "var paycode=" + "'" + getIframeHTML () + "';\n\n" +
                  "var save_checkout_html;\n\n" +
                  "var transaction_channel = new XMLHttpRequest();\n\n" +
                  "var shopping_enabled = true;\n\n" +
                  "var next_reference_id = 100000;\n\n" +
                  "var payment_status = '" + Messages.INITIALIZE + "';\n\n") +
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
            "<tr><td style=\"text-align:center\">Total Amount</td><td style=\"text-align:right\" id=\"total\">")
         .append (price (saved_shopping_cart.total))
         .append("</td><td style=\"border-width:1px 0px 0px 1px;background:white\"></td></tr>" +
                 "</table></td></tr>" +
                 "<tr><td style=\"text-align:center;padding-top:10pt\" id=\"pay\">")
         .append (getIframeHTML ())
         .append ("</td></tr></table></td></tr>" +
                  "<form name=\"shoot\" method=\"POST\" action=\"authreq\">" +
                  "<input type=\"hidden\" name=\"authreq\" id=\"authreq\">" +
                  "</form>" +
                  "<form name=\"restore\" method=\"POST\" action=\"" + Init.merchant_url + "\">" +
                  "</form>");
        
     StringBuffer temp_string = new StringBuffer (
        "\n\n\"use strict\";\n\n" +
        "var payment_status = '" + Messages.INITIALIZE + "';\n\n" +
        "function receivePaymentMessage(event) {\n" +
        "    console.debug (event.origin + ' = > Checkout:\\n' + event.data);\n" +
        "    var received_json = JSON.parse(event.data);\n" +
        "    if (received_json['" + JSONDecoderCache.CONTEXT_JSON + "'] != '" + WCPP_DEMO_CONTEXT_URI + "') {\n" +
        "        console.debug('UNDECODABLE MESSAGE');\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] == '" + Messages.ABORT + "') {\n" +
        "        document.forms.restore.submit();\n" +
        "        return;\n" +
        "    }\n" +
        "    if (received_json['" + JSONDecoderCache.QUALIFIER_JSON + "'] != payment_status) {\n" +
        "        console.debug('STATE ERROR: ' + event.data + '/' + payment_status);\n" +
        "        return;\n" +
        "    }\n" +
        "    if (payment_status == '" + Messages.INITIALIZE + "') {\n" +
        "        setTimeout(function(){\n" +
        "        event.source.postMessage(" + invoke_json + ", event.origin);\n" +
//      "        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
        "        }, 500);\n" +
        "        payment_status = '" + Messages.AUTHORIZE + "';\n" +
        "    } else {\n" +
        "        document.getElementById('authreq').value = JSON.stringify(received_json);\n" +
        "        document.forms.shoot.submit();\n" +
        "    }\n" +
        "}\n\n" +
        "function initPage() {\n" +
        "    window.addEventListener('message', receivePaymentMessage, false);\n" +
        "}\n");
        HTML.output (response, HTML.getHTML (temp_string.toString (), "onload=\"initPage()\"", s.toString ()));
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
             "<tr><td><table>" +
             "<tr><td style=\"padding-bottom:8pt\">Dear customer, your order has been successfully processed!</td></tr>" +
             "<tr><td>Amount: ")
            .append (price (payment_request.amount))
            .append ("</td></tr><tr><td>")
            .append (card_type)
            .append (": ")
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
