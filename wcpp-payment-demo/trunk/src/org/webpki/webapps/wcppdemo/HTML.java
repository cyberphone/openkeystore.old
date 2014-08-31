package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.Vector;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class HTML
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

    // Common property of all commands, argument holds verb
    static final String PAYMENT_API_COMMAND              = "Command";
    
    static final String PAYMENT_API_INIT_COMMAND         = "INIT";
    // Payment application received INIT data
    static final String PAYMENT_API_INIT_REC_AMOUNT      = "Amount";
    static final String PAYMENT_API_INIT_REC_CURRENCY    = "Currency";
    static final String PAYMENT_API_INIT_REC_CARD_TYPES  = "CardTypes";
    static final String PAYMENT_API_INIT_REC_COMMON_NAME = "CommonName";
    
    static final String PAYMENT_API_ABORT_COMMAND        = "ABORT";
    static final String PAYMENT_API_FINAL_COMMAND        = "FINAL";
    
    static final String HTML_INIT = 
	    "<!DOCTYPE html>"+
	    "<html><head><meta charset=\"UTF-8\"><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
//        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
	    "<title>WebCrypto++ Payment Demo</title>"+
	    "<style type=\"text/css\">html {overflow:auto}\n"+
	    ".tftable {border-collapse: collapse}\n" +
	    ".tftable th {font-size:10pt;background: linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
	    ".tftable tr {background-color:#FFFFE0}\n" +
	    ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;font-family:arial,verdana,helvetica}\n" +
	    "body {font-size:10pt;color:#000000;font-family:verdana,arial;background-color:white}\n" +
	    "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica}\n" +
	    "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica}\n" +
	    "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}\n" +
	    "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}\n" +
	    "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana}\n" +
	    "td {font-size:8pt;font-family:verdana,arial}\n" +
	    ".smalltext {font-size:6pt;font-family:verdana,arial}\n" +
	    "input[type='button'] {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px}\n" +
	    ".headline {font-weight:bolder;font-size:10pt;font-family:arial,verdana}\n";
	

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
            s.append (' ').append (bodyscript);
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
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">WebCrypto++ Payment Demo<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">This site contains a demo of what a true WebCrypto++ implementation " +
                   "could offer for <span style=\"color:red\">decentralized payment systems</span>.</td></tr>" +
                   "<tr><td align=\"left\">In particular note the <span style=\"color:red\">automatic payment card discovery</span> process " +
                   "and that <span style=\"color:red\">payment card logotypes are personalized</span> since they "+
                   "are read from the user's local key-store.</td></tr>" +
                   "<tr><td align=\"left\">Although the demo is a mockup (no &quot;polyfill&quot; in the world can replace WebCrypto++), " +
                   "the IFRAME solution and cross-domain communication using <code>postMessage()</code> should be pretty close to that of a real system.</td></tr>" +
                   "<tr><td align=\"center\"><table cellspacing=\"10\">" +
                   "<tr align=\"left\"><td><a href=\"" + Init.bank_url + "/cards\">Initialize Payment Cards</a></td><td><i>Mandatory</i> First Step</td></tr>" +
                   "<tr align=\"left\"><td><a href=\"" + Init.merchant_url + "\">Go To Merchant</a></td><td>Shop Til You Drop!</td></tr>" +
                   "<tr align=\"left\"><td><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/pki-webcrypto.pdf\">WebCrypto++</a></td><td>The Specification</td></tr>" +
                   "<tr align=\"left\"><td><a target=\"_blank\" href=\"https://code.google.com/p/openkeystore/source/browse/#svn/wcpp-payment-demo\">Source Code</a></td><td>For Nerds...</td></tr>" +
                 "</table></td></tr></table></td></tr>"));
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
            else if (c == '\'')
              {
                s.append ("\\'");
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
	    "body {font-size:10pt;color:#000000;font-family:Arial,Verdana,Helvetica;background-color:white;margin:0px;padding:0px}\n" +
	    "table {border-collapse: collapse}\n" +
	    "td {padding: 0px}\n" +
        "</style></head><body onload=\"initPayment()\">" +
	    "<div id=\"border\" style=\"font-family:Verdana,Arial,Helvetica;padding:" + PAYMENT_DIV_VERTICAL_PADDING + "px " +
        PAYMENT_DIV_HORIZONTAL_PADDING + "px " + PAYMENT_DIV_VERTICAL_PADDING + "px " +
	    PAYMENT_DIV_HORIZONTAL_PADDING + "px;" +
        "color:white;background:" +
        PAYMENT_BORDER_COLOR + ";width:" +
        (PAYMENT_WINDOW_WIDTH - (PAYMENT_DIV_HORIZONTAL_PADDING * 2)) +"px\">&nbsp;</div>" +
	    "<div id=\"activity\" style=\"padding:" + PAYMENT_DIV_VERTICAL_PADDING + "px " + 
        PAYMENT_DIV_HORIZONTAL_PADDING + "px " + PAYMENT_DIV_VERTICAL_PADDING + "px " + 
	    PAYMENT_DIV_HORIZONTAL_PADDING + "px\">" +
        "Initializing...</div>" +
	    "<div id=\"content\" style=\"overflow-y:auto;\"></div>" +
        "<div id=\"control\" style=\"z-index:3;position:absolute;bottom:0px;width:" + PAYMENT_WINDOW_WIDTH +"px;padding-top:5px;padding-bottom:10pt\">" +
	    "<input id=\"cancel\" type=\"button\" value=\"&nbsp;Cancel&nbsp;\" style=\"position:relative;visibility:hidden\" onclick=\"userAbort()\">" +
        "<input id=\"ok\" type=\"button\" value=\"OK\" style=\"position:relative;visibility:hidden\" title=\"Authorize Payment!\" onclick=\"userAuthorize()\"></div>" +
        "<img id=\"busy\" src=\"images/loading.gif\" alt=\"html5 requirement...\" style=\"position:absolute;top:" + 
        ((PAYMENT_WINDOW_HEIGHT - PAYMENT_LOADING_SIZE) / 2) + "px;left:" + 
        ((PAYMENT_WINDOW_WIDTH - PAYMENT_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<script type=\"text/javascript\">\n" +
        "\"use strict\";\n\n" +
        "////////////////////////////////////////////////////////////////////\n" +
        "// Disclaimer: The actual messages used by this payment provider  //\n" +
        "// in no way represents a standard or a standards proposal.       //\n" +
        "// However, the message flow is anticipated to be usable \"as is\". //\n" +
        "////////////////////////////////////////////////////////////////////\n\n" +
        "var aborted_operation = false;\n" +
        "var timeouter_handle = null;\n" +
        "var amount_to_pay;\n" +
        "var currency;\n" +
        "var caller_common_name;\n" +
        "var payment_state = '" + PAYMENT_API_INIT_COMMAND + "';\n" +
        "var button_width;\n" +
        "var webpki = {};\n" +
        "webpki.CardEntry = function(base64_image, type, pin, pan) {\n" +
        "    this.base64_image = base64_image;\n" +
        "    this.type = type;\n" +
        "    this.pin = pin;\n" +
        "    this.pan = pan;\n" +
        "    this.matching = false;\n" +
        "};\n" +
        "var card_list = [];\n");
        HttpSession session = request.getSession (false);
        if (session != null)
        {
        	@SuppressWarnings("unchecked")
			Vector<CardEntry> card_entries = (Vector<CardEntry>) session.getAttribute(CardEntry.CARD_LIST);
        	if (card_entries != null)
        	{
        		int i = 0;
        		for (CardEntry card_entry : card_entries)
        		{
        			if (card_entry.active)
        			{
            			s.append("card_list[")
	           			 .append (i++)
	           			 .append("] = new webpki.CardEntry('")
	           			 .append(card_entry.base64_image)
	           			 .append("', '")
	           			 .append(card_entry.card_type.toString())
                         .append("', '")
                         .append(card_entry.pin == null ? CardEntry.DEFAULT_PIN : card_entry.pin)
                         .append("', '")
                         .append(card_entry.pan)
                         .append ("');\n");
        			}
        		}
        	}
        }
        s.append (
        "\nfunction bad(message) {\n" +
        "    console.debug ('Bad: ' + message);\n" +
        "    if (!aborted_operation) {\n" +
        "        document.getElementById('activity').innerHTML='ABORTED:<br>' + message;\n" +
        "        aborted_operation = true;\n" +
        "    }\n" +
        "    document.getElementById('busy').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function checkNoErrors() {\n" +
        "   if (aborted_operation || window.self.innerWidth != " + PAYMENT_WINDOW_WIDTH + " || window.self.innerHeight != " + PAYMENT_WINDOW_HEIGHT + ") {\n" +
        "       bad('Frame size manipulated by parent');\n" +
        "       return false;\n" +
        "   }\n" +
        "   if (!card_list.length) {\n" +
        "       bad('You appear to have no payment cards at all, please return " +
            "to the <b>Payment&nbsp;Demo&nbsp;Home</b> and get some!  It\\'s free :-)');\n" +
        "       return false;\n" +
        "   }\n" +
        "   return true;\n" +
        "}\n\n" +
        "function checkTiming(milliseconds) {\n" +
        "   timeouter_handle = setTimeout(function () {bad('Timeout')}, milliseconds);\n" +
        "}\n\n" +
        "function checkState(event) {\n" +
        "    var json = JSON.parse(event.data);\n" +
        "    if (json." + PAYMENT_API_COMMAND + " != payment_state) {\n" +
        "        bad('State error:' + payment_state + '<>' + event.data);\n" +
        "        return null;\n" +
        "    }\n" +
        "    return json;\n" +
        "}\n\n" +
        "function priceString(price_mult_100) {\n" +
        "    return '$' +  Math.floor(price_mult_100 / 100) + '.' +  Math.floor((price_mult_100 % 100) / 10) +  Math.floor(price_mult_100 % 10);\n" +
        "}\n\n" +
        "function createJSONBaseCommand(command_property_value) {\n" +
        "    var json = {};\n" +
        "    json." + PAYMENT_API_COMMAND + " = command_property_value;\n" +
        "    return json;\n" +
        "}\n\n" +
        "function getJSONPropertyValue(json, property) {\n" +
        "    var value = json[property];\n" +
        "    console.debug(property + ': ' + value);\n" +
        "    if (value === undefined) {\n" +
        "        bad('Missing property: ' + property);\n" +
        "        return null;\n" +
        "    }\n" +
        "    return value;\n" +
        "}\n\n" +
        "function cardTableHeader(right_margin, top_margin) {\n" +
        "    return '<table style=\"" +
            "margin-left:auto;margin-right:' + right_margin + ';margin-top:' + top_margin + 'px\">';\n" +
        "}\n\n" +
        "function outputCard(card_index, add_on) {\n" +
        "    return '<td>' + '" + 
             javaScript (CardEntry.CARD_DIV) +
             "' + card_list[card_index].base64_image + '\\')' + add_on + '\">" +
             "</div></td>';\n" +
        "}\n\n" +
        "//\n" +
        "// Although PANs (card numbers) are not really needed from the user's\n" +
        "// point of view, they represent a legacy which should not be ignored...\n" +
        "//\n" +
        "function outputPAN(card_index) {\n" +
        "    var pan_html = '<td style=\"padding-top:" + PAYMENT_PAN_PADDING_TOP +
             "px;padding-bottom:" + PAYMENT_PAN_PADDING_BOTTOM + "px;font-size:8pt;font-family:Verdana;text-align:center\">';\n" +
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
        "    var payment_details = '<table id=\"details\" style=\"position:absolute;text-align:center\">" +
             "<tr><td>Requester: ' + caller_common_name + '</td></tr>" +
             "<tr><td style=\"padding-top:10pt;padding-bottom:10pt\">Amount: ' + priceString(amount_to_pay) + '</td></tr>" +
             "<tr><td>PIN: <input id=\"pin\" " +
             "style=\"font-family:Verdana,Arial;letter-spacing:2px;background-color:#f0f0f0\" " +
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
        "    var details_left = document.getElementById('details').style.left = (" +
             (PAYMENT_WINDOW_WIDTH - CardEntry.CARD_WIDTH - PAYMENT_CARD_RIGHT_MARGIN) +
             " - document.getElementById('details').offsetWidth) / 2;\n" +
             "    document.getElementById('details').style.left = details_left + 'px';\n" +
             "    document.getElementById('ok').style.left = ((details_left + " +
                 "document.getElementById('pin').offsetLeft - " +
                 "button_width) * 2 + document.getElementById('pin').offsetWidth - " +
                 PAYMENT_BUTTON_LEFT + ") + 'px';\n" +
        "    document.getElementById('ok').style.visibility = 'visible';\n" +
        "    document.getElementById('pin').title = 'Forgot PIN? Try with ' + card_list[card_index].pin + ' :-)';\n" +
        "    document.getElementById('pin').focus();\n" +
        "}\n\n" +
        "//\n" +
        "// Displays payee compatible cards for the user to select from.\n" +
        "// If the card collection does not fit in payment window,\n" +
        "// a scrollable view is created.\n" +
        "//\n" +
        "function displayCompatibleCards(count) {\n" +
        "    document.getElementById('activity').innerHTML = 'Select Card';\n" +
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
            PAYMENT_API_ABORT_COMMAND + "')), window.document.referrer);\n" +
       "}\n\n" +
       "//\n" +
       "// Called when the user authorized the payment.\n" +
       "//\n" +
       "function userAuthorize() {\n" +
        "    document.getElementById('busy').style.visibility = 'visible';\n" +
        "    alert ('not implemented');\n" +
//       "    window.parent.postMessage('" + PAYMENT_API_ABORT + "', window.document.referrer);\n" +
       "}\n\n" +
       "//\n" +
       "// Processes the payee's JSON response to the INIT message.\n" +
       "//\n" +
       "// Message syntax:\n" +
       "//   {\n" +
       "//     \"" + PAYMENT_API_COMMAND + "\": \"" + PAYMENT_API_INIT_COMMAND + "\"\n" +
       "//     \"" + PAYMENT_API_INIT_REC_AMOUNT + "\": nnnn                   Integer of the payment sum multiplied by 100\n" +
       "//     \"" + PAYMENT_API_INIT_REC_CURRENCY + "\": \"USD\"                Currently the only recognized\n" +
       "//     \"" + PAYMENT_API_INIT_REC_COMMON_NAME + "\": \"Name\"             Common name of requester\n" +
       "//     \"" + PAYMENT_API_INIT_REC_CARD_TYPES + "\": [\"Card Type\"...]    1-n card types recognized by the payee\n" +
       "//   }\n" +
       "//\n" +
       "function processINIT(received_json) {\n" +
       "    caller_common_name = getJSONPropertyValue(received_json, '" + PAYMENT_API_INIT_REC_COMMON_NAME + "');\n" +
       "    amount_to_pay = getJSONPropertyValue(received_json, '" + PAYMENT_API_INIT_REC_AMOUNT + "');\n" +
       "    currency = getJSONPropertyValue(received_json, '" + PAYMENT_API_INIT_REC_CURRENCY + "');\n" +
       "    var payee_card_types = getJSONPropertyValue(received_json, '" + PAYMENT_API_INIT_REC_CARD_TYPES + "');\n" +
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
       "    button_width = document.getElementById('cancel').offsetWidth;\n" +
       "    document.getElementById('ok').style.width = button_width + 'px';\n" +
       "    document.getElementById('cancel').style.left = ((" +
            PAYMENT_WINDOW_WIDTH + " - button_width) / 2) + 'px';\n" +
       "    document.getElementById('cancel').title = 'Cancel and return to \"' + caller_common_name + '\"';\n" +
       "    document.getElementById('cancel').style.visibility = 'visible';\n" +
       "    if (!count) {\n" +
       "        bad('No matching payment cards found, click \"Cancel\" to return to \"' + caller_common_name + '\".');\n" +
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
//       "    window.parent.postMessage('" + PAYMENT_API_FINAL + "', window.document.referrer);\n" +
       "}\n\n" +
       "//\n" +
       "// The payment application always query the payee for data.\n" +
       "// There is a timeout associated each request.\n" +
       "//\n" +
		"function receivePayeeResponse(event) {\n" +
		"    console.debug(event.origin);\n" +
		"    console.debug(event.data);\n" +
		"    if (aborted_operation) return;\n" +
		"    if (timeouter_handle) {\n" +
		"        clearTimeout(timeouter_handle);\n" +
		"        timeouter_handle = null;\n" +
		"        var received_json = checkState(event)\n" +
		"        if (!received_json) return;\n" +
        "        document.getElementById('busy').style.visibility = 'hidden';\n" +
		"        if (payment_state == '" + PAYMENT_API_INIT_COMMAND + "') {\n" +
        "            processINIT(received_json);\n" +
		"        }\n" +
		"    } else {\n" +
		"        bad('Unexpected message :' + event.origin + ' ' + event.data);\n" +
		"    }\n" +
		"}\n\n" +
		"//\n" +
		"// When the payment module IFRAME has been loaded (by the payee),\n" +
		"// the payment process is automatically invoked by the body.onload().\n" +
        "//\n" +
        "function initPayment() {\n" +
        "    var caller_domain = window.document.referrer;\n" +
        "    caller_domain = caller_domain.substring(caller_domain.indexOf('://') + 3);\n" +
        "    if (caller_domain.indexOf(':') > 0) {\n" +
        "        caller_domain = caller_domain.substring(0, caller_domain.indexOf(':'));\n" +
        "    }\n" +
        "    if (caller_domain.indexOf('/') > 0) {\n" +
        "        caller_domain = caller_domain.substring(0, caller_domain.indexOf('/'));\n" +
        "    }\n" +
        "    document.getElementById('border').innerHTML = 'Payment Request [' + caller_domain + ']';\n" +
        "    if (checkNoErrors()) {\n" +
		"        window.addEventListener('message', receivePayeeResponse, false);\n" +
        "        checkTiming(" + PAYMENT_TIMEOUT_INIT + ");\n" +
        "        console.debug('init payment window');\n" +
        "        window.parent.postMessage(JSON.stringify(createJSONBaseCommand ('" +
                 PAYMENT_API_INIT_COMMAND + "')), window.document.referrer);\n" +
        "    }\n" +
        "}\n" +
        "</script>" +
        "</body></html>");
        HTML.output (response, s.toString());
	  }

	static StringBuffer temp_string;
	static int temp_counter;

	private static String productEntry (String image_url, String name, int price_mult_100)
	  {
		String prod_entry = "p" + temp_counter;
		String s = "<tr style=\"text-align:center\"><td><img src=\"images/" + image_url +
				   "\"></td><td>" + name + "</td><td style=\"text-align:right\">" + price  (price_mult_100) +
				   "</td><td><form>" +
					   "<table style=\"border-width:0px;padding:0px;margin:0px;border-spacing:2px;border-collapse:separate\">" +
					   "<tr>" +
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" value=\"&#x25b2;\" title=\"More\" onclick=\"updateUnits(this.form." + prod_entry + ", 1, " + temp_counter + ")\" style=\"text-align:center;margin:0px;padding:0px\" ></td>" +
					   "</tr>" +
					   "<tr>" +
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input size=\"6\" type=\"text\" name=\"" + 
					       prod_entry + 
					       "\" value=\"0\" style=\"text-align:right\" " +
					       "oninput=\"updateInput(" + temp_counter + ", this);\" autocomplete=\"off\"/></td>" +
					   "</tr>" +
					   "<tr>" +
		               "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" value=\"&#x25bc;\" title=\"Less\" onclick=\"updateUnits(this.form." + prod_entry + ", -1, " + temp_counter + ")\" style=\"text-align:center;margin:0px;padding:0px\" ></td>" +
					   "</tr>" +
					   "</table></form></td></tr>";
        temp_string.insert (0, "shopping_cart[" + temp_counter + "] = new webpki.ShopEntry(" + price_mult_100 + ");\n");		
		temp_counter++;
		return s;
	  }

	private static String price (int price_mult_100) 
	  {
		return "$" + String.valueOf (price_mult_100 / 100) + "." + String.valueOf ((price_mult_100 % 100) / 10) + String.valueOf (price_mult_100 % 10);
	  }
	
	public static void merchantPage (HttpServletResponse response) throws IOException, ServletException
	  {
		temp_counter = 0;
		temp_string = new StringBuffer (
        	"\nfunction checkOut() {\n" +
            "    if (getTotal()) {\n" +
            "        shopping_enabled = false;\n" +
    		"        window.addEventListener('message', receivePaymentMessage, false);\n" +
            "        save_checkout_html = document.getElementById('pay').innerHTML;\n" +
            "        document.getElementById('pay').innerHTML = paycode;\n" +
            "    } else {\n" +
            "        alert('Nothing ordered!');\n" +
            "    }\n" +
	        "}\n\n" +
		    "function getTotal() {\n" +
	        "    var total = 0;\n" +
	        "    for (var i = 0; i < shopping_cart.length; i++) {\n" +
	        "        total += shopping_cart[i].price_mult_100 * shopping_cart[i].units;\n" +
            "    }\n" +
	        "    return total;\n"+
	        "}\n\n" +
	        "function priceString(price_mult_100) {\n" +
	        "    return '$' +  Math.floor(price_mult_100 / 100) + '.' +  Math.floor((price_mult_100 % 100) / 10) +  Math.floor(price_mult_100 % 10);\n" +
	        "}\n\n" +
	        "function updateTotal(){\n" +
            "    document.getElementById('total').innerHTML = priceString(getTotal());\n" +
	        "}\n\n" +
	        "function updateInput(index, control) {\n" +
	        "    if (shopping_enabled) {\n" +
	        "        if (!numeric_only.test (control.value)) control.value = '0';\n" +
	        "        while (control.value.length > 1 && control.value.charAt(0) == '0') control.value = control.value.substring(1);\n" +
	        "        shopping_cart[index].units = control.value;\n" +
	        "        updateTotal();\n" +
	        "    } else {\n" +
	        "        control.value = shopping_cart[index].units;\n" +
	        "    }\n" +
	        "}\n\n" +
            "function updateUnits(control, value, index) {\n" +
            "    control.value = parseInt(control.value) + value;\n" +
            "    updateInput(index, control);\n" +
	        "}\n\n" +
	        "function createJSONBaseCommand(command_property_value) {\n" +
	        "    var json = {};\n" +
	        "    json." + PAYMENT_API_COMMAND + " = command_property_value;\n" +
	        "    return json;\n" +
	        "}\n\n" +
			"function receivePaymentMessage(event) {\n" +
			"    console.debug (event.origin);\n" +
			"    console.debug (event.data);\n" +
			"    var received_json = JSON.parse(event.data);\n" +
            "    if (received_json." + PAYMENT_API_COMMAND + " == '" + PAYMENT_API_ABORT_COMMAND + "') {\n" +
            "        document.getElementById('pay').innerHTML = save_checkout_html;\n" +
            "        payment_status = '" + PAYMENT_API_INIT_COMMAND + "';\n" +
            "        shopping_enabled = true;\n" +
			"        return;\n" +
			"    }\n" +
			"    if (received_json." + PAYMENT_API_COMMAND + " != payment_status) {\n" +
			"        console.debug('STATE ERROR: ' + event.data + '/' + payment_status);\n" +
			"        payment_status = 'Failed***';\n" +
			"        return;\n" +
			"    }\n" +
			"    if (payment_status == '" + PAYMENT_API_INIT_COMMAND + "') {\n" +
			"        setTimeout(function(){\n" +
			"        var returned_json = createJSONBaseCommand('" + PAYMENT_API_INIT_COMMAND + "');\n" +
            "        returned_json." + PAYMENT_API_INIT_REC_COMMON_NAME + " = 'Demo Merchant';\n" +
            "        returned_json." + PAYMENT_API_INIT_REC_CURRENCY + " = 'USD';\n" +
			"        returned_json." + PAYMENT_API_INIT_REC_AMOUNT + " = getTotal();\n" +
            "        returned_json." + PAYMENT_API_INIT_REC_CARD_TYPES + " = [];\n" +
            "        returned_json." + PAYMENT_API_INIT_REC_CARD_TYPES + ".push('NEVER_HEARD_OF_CARD');\n");
            for (CardTypes card_type : MerchantServlet.compatible_with_merchant)
              {
                temp_string.append ("        returned_json." + PAYMENT_API_INIT_REC_CARD_TYPES + ".push('")
                           .append (card_type.toString())
                           .append ("');\n");
              }
        temp_string.append (
            "        event.source.postMessage(JSON.stringify(returned_json), event.origin);\n" +
//			"        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
			"        }, 500);\n" +
			"        payment_status = '" + PAYMENT_API_FINAL_COMMAND + "';\n" +
			"    }\n" +
			"    else if (payment_status == '" + PAYMENT_API_FINAL_COMMAND + "') {\n" +
            "        document.getElementById('result').innerHTML = 'Yes!!!';\n" +
 //           "        document.getElementById('pay').innerHTML = '';\n" +
			"    }\n" +
			"}\n");

		StringBuffer page_data = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<table>" +
               "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Demo Merchant<br>&nbsp;</td></tr>" +
               "<tr><td id=\"result\"><table style=\"margin-left:auto;margin-right:auto\" class=\"tftable\">" +
       		       "<tr><th>Image</th><th>Description</th><th>Price</th><th>Units</th></tr>" +
                   productEntry ("product-car.png", "Sports Car", 8599900) + 
                   productEntry ("product-icecream.png", "Ice Cream", 325) + 
       		       "<tr><td style=\"border-width:1px 1px 0px 0px;background:white\"></td><td style=\"text-align:center\">Total Amount</td><td style=\"text-align:right\" id=\"total\">$0.00</td><td style=\"border-width:1px 0px 0px 1px;background:white\"></td></tr>" +
               "</table></td></tr>" +
               "<tr><td style=\"text-align:center\" id=\"pay\"><input style=\"font-size:10pt\" type=\"button\" value=\"Checkout..\" title=\"Paying time has come...\" onclick=\"checkOut ()\"></td></tr>" +
             "</table></td></tr>");
		temp_string.insert (0,
		        "\n\"use strict\";" +
                "\nvar paycode=" + 
	            "'<iframe src=\"" + Init.bank_url + "/payment\" style=\"width:" + PAYMENT_WINDOW_WIDTH + "px;height:" + PAYMENT_WINDOW_HEIGHT + "px;border-width:1px;border-style:solid;border-color:" +
	            PAYMENT_BORDER_COLOR + ";box-shadow:3pt 3pt 3pt #D0D0D0\"></iframe>';\n\n" +
	            "var save_checkout_html;\n\n" +
				"var numeric_only = new RegExp('^[0-9]{1,6}$');\n\n" +
				"var shopping_cart = [];\n" +
	            "var shopping_enabled = true;\n" +
				"var payment_status = '" + PAYMENT_API_INIT_COMMAND + "';\n" +
	            "var webpki = {};\n" +
		        "webpki.ShopEntry = function(price_mult_100) {\n" +
		        "    this.price_mult_100 = price_mult_100;\n" +
		        "    this.units = 0;\n" +
		        "};\n");

        HTML.output (response, HTML.getHTML (temp_string.toString(), null, page_data.toString()));
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
            "<table cellpadding=\"0\" cellspacing=\"0\"><tr><td></td><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Your Payment Cards<br>&nbsp;</td></tr>" +
	        "<tr><td colspan=\"2\"><table style=\"margin-bottom:10pt;margin-left:auto;margin-right:auto\">" +
	        "<tr><td style=\"font-size:10pt\">Name</td><td><input size=\"18\" type=\"text\" maxlength=\"35\" placeholder=\"Name on the card\" name=\"" + CardEntry.USER_FIELD + "\" value=\"")
	    .append (card_entries.firstElement ().user == null ? "" : encode (card_entries.firstElement ().user))
	    .append ("\"></td></tr>" +
	        "<tr><td style=\"font-size:10pt\">PIN</td><td><input size=\"18\" type=\"text\" maxlength=\"" +
	        PIN_MAX_LENGTH + "\" placeholder=\"Default: " + 
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
             .append (" recognized by the demo merchant\">" +
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
  }
