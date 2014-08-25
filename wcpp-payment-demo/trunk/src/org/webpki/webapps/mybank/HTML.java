package org.webpki.webapps.mybank;

import java.io.IOException;

import java.util.Vector;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class HTML
  {
    static final String SIGNUP_BGND_COLOR   = "#F4FFF1";
	static final String SIGNUP_EDIT_COLOR   = "#FFFA91";
    static final String SIGNUP_BAD_COLOR    = "#F78181";
	static final String BOX_SHADDOW         = "box-shadow:5px 5px 5px #C0C0C0";
	static final String KG2_DEVID_BASE      = "Field";

    static final String TEXT_BOX   = "background:#FFFFD0;width:805pt;";
    
   
    static final int PAYMENT_WINDOW_WIDTH           = 450;
    static final int PAYMENT_WINDOW_HEIGHT          = 250;
    static final int PAYMENT_LOADING_SIZE           = 48;
    static final int PAYMENT_DIV_HORIZONTAL_PADDING = 6;
    static final int PAYMENT_DIV_VERTICAL_PADDING   = 5;
    static final String PAYMENT_BORDER_COLOR        = "#306754";

    static final int PAYMENT_TIMEOUT_INIT           = 5000;
    
    static final String PAYMENT_API_INIT             = "INIT";
    static final String PAYMENT_API_FINAL            = "FINAL";
    
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
	    "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white}\n" +
	    "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica}\n" +
	    "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica}\n" +
	    "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}\n" +
	    "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}\n" +
	    "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana}\n" +
	    "input[type=text] {font-weight:normal;font-size:8pt;font-family:verdana,arial}\n" +
	    "td {font-size:8pt;font-family:verdana,arial}\n" +
	    ".smalltext {font-size:6pt;font-family:verdana,arial}\n" +
	    "input[type=button] {cursor:pointer;font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px}\n" +
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

    static String getConditionalParameter (HttpServletRequest request, String name)
      {
        String value = request.getParameter (name);
        if (value == null)
          {
            return "";
          }
        return value;
      }

    public static void homePage (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width:600px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">WebCrypto++ Payment Demo<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">This site contains a demo of what a true WebCrypto++ implementation " +
                   "could offer for <span style=\"color:red\">decentralized payment systems</span>.</td></tr>" +
                   "<tr><td align=\"left\">In particular note the <span style=\"color:red\">automatic payment card discovery</span> process " +
                   "and that <span style=\"color:red\">payment card logotypes are personalized</span> since they "+
                   "comes from the user's local key-store.</td></tr>" +
                   "<tr><td align=\"left\">Although the demo is a mockup (no &quot;polyfill&quot; in the world can replace WebCrypto++), " +
                   "the IFRAME solution and cross-domain communication should be pretty close to that of a real system.</td></tr>" +
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
	    "<html><head>"+
	    "<style type=\"text/css\">html {overflow:auto}\n"+
	    "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white;margin:0px;padding:0px}\n" +
	    "div {padding:" + PAYMENT_DIV_VERTICAL_PADDING + "px " + PAYMENT_DIV_HORIZONTAL_PADDING + "px " + PAYMENT_DIV_VERTICAL_PADDING + "px " + PAYMENT_DIV_HORIZONTAL_PADDING + "px}\n" +
	    "input[type=button] {cursor:pointer;font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px}\n"+
        "</style></head><body onload=\"initPayment ()\"><div style=\"color:white;font-size:10pt;background:" +
        PAYMENT_BORDER_COLOR + ";width:" + (PAYMENT_WINDOW_WIDTH - (PAYMENT_DIV_HORIZONTAL_PADDING * 2)) +"px\">Payment Request</div><div id=\"main\">Initializing...</div>" +
        "<img id=\"busy\" src=\"images/loading.gif\" style=\"position:absolute;top:" + ((PAYMENT_WINDOW_HEIGHT - PAYMENT_LOADING_SIZE) / 2) + "px;left:" + ((PAYMENT_WINDOW_WIDTH - PAYMENT_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<script type=\"text/javascript\">\n" +
        "var aborted_operation = false;\n" +
        "var timeouter_handle = null;\n" +
        "var payment_state = '" + PAYMENT_API_INIT + "';\n" +
        "CardEntry = function (base64_image, type, pin, pan) {\n" +
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
	           			 .append("] = new CardEntry ('")
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
        "\nfunction bad (message) {\n" +
        "    if (!aborted_operation) {\n" +
        "        document.getElementById ('main').innerHTML='ABORTED:<br>' + message;\n" +
        "        aborted_operation = true;\n" +
        "    }\n" +
        "    document.getElementById ('busy').style.visibility = 'hidden';\n" +
        "}\n\n" +
        "function checkNoErrors () {\n" +
        "   if (aborted_operation || window.self.innerWidth != " + PAYMENT_WINDOW_WIDTH + " || window.self.innerHeight != " + PAYMENT_WINDOW_HEIGHT + ") {\n" +
        "       bad ('Frame size manipulated by parent');\n" +
        "       return false;\n" +
        "   }\n" +
        "   if (!card_list.length) {\n" +
        "       bad ('You appear to have no payment cards at all, please return to the Payment Demo Home and get some!');\n" +
        "       return false;\n" +
        "   }\n" +
        "   return true;\n" +
        "}\n\n" +
        "function checkTiming (milliseconds) {\n" +
        "   timeouter_handle = setTimeout (function () {bad ('Timeout')}, milliseconds);\n" +
        "}\n\n" +
        "function checkState (event) {\n" +
        "   if (event.data.indexOf (payment_state)) {\n" +
        "       bad ('State error:' + payment_state + '<>' + event.data);\n" +
        "       return null;\n" +
        "   }\n" +
        "   if (event.data.length < (payment_state.length + 2) || event.data.charAt (payment_state.length) != '=') {\n" +
        "       bad ('Missing argument: ' + event.data);\n" +
        "       return null;\n" +
        "   }\n" +
        "   return event.data.substring (payment_state.length + 1);\n" +
        "}\n\n" +
        "function oneCard (card_index, add_on) {\n" +
        "    return '<tr><td>' + '" +
             CardEntry.CARD_DIV_1 + 
             "' + card_list[card_index].pan + '" +
             javaScript (CardEntry.CARD_DIV_2) +
             "' + card_list[card_index].base64_image + '\\')' + add_on + '\">" +
             "</div></td></tr>';\n" +
        "}\n\n" +
        "function payDisplay (card_index) {\n" +
        "   document.getElementById ('main').innerHTML='<table style=\"margin:auto\">" +
            "<tr><td>You gonna pay dude!</td></tr>' + " +
            "oneCard (card_index, '') + '</table>';\n" +
        "}\n\n" +
        "function cardDisplay () {\n" +
        "    var cards = '<table style=\"margin:auto\">" +
            "<tr><td>Select Card</td></tr>';\n" +
        "    for (var q = 0; q < card_list.length; q++) {\n" +
        "        if (card_list[q].matching) {\n"+
        "            cards += oneCard (q, ';cursor:pointer\" onclick=\"payDisplay (' + q + ')');\n" +
        "        }\n" +
        "    }\n" +
        "   document.getElementById ('main').innerHTML=cards + '</table>';\n" +
       "}\n\n" +
		"function receiveMessage (event) {\n" +
		"    console.debug (event.origin);\n" +
		"    console.debug (event.data);\n" +
		"    if (aborted_operation) return;\n" +
		"    if (timeouter_handle) {\n" +
		"        clearTimeout (timeouter_handle);\n" +
		"        timeouter_handle = null;\n" +
		"        var res = checkState (event)\n" +
		"        if (!res) return;\n" +
        "        document.getElementById ('busy').style.visibility = 'hidden';\n" +
		"        if (payment_state == '" + PAYMENT_API_INIT + "') {\n" +
        "            var amount = res.substring (0, res.indexOf ('@'));\n" +
		"            console.debug ('Amount: ' + amount);\n" +
        "            var found = 0;\n" +
        "            while (res.indexOf ('@') >= 0) {\n" +
		"                res = res.substring (res.indexOf ('@') + 1);\n" +
		"                var i = res.indexOf ('@');\n" +
        "                card = i > 0 ? res.substring (0, i) : res;\n" +
        "                console.debug ('Card: \"' + card + '\"');\n" + 
        "                for (i = 0; i < card_list.length; i++) {\n" +
        "                    if (card == card_list[i].type) {\n" +
        "                        card_list[i].matching = true;\n" +
        "                        found++;\n" +
        "                    }\n" +
        "                }\n" +
        "            }\n" +
        "            if (!found) {\n" +
        "                bad ('No matching payment card found!');\n" +
        "                return;\n" +
        "            }\n" +
        "            for (var q = 0; q < card_list.length; q++) {\n" +
        "                if (card_list[q].matching) {\n"+
        "                    console.debug ('Matching card: ' + card_list[q].type);\n" +
        "                }\n" +
        "            }\n" +
        "            if (found == 1) {\n" +
        "                for (var q = 0; q < card_list.length; q++) {\n" +
        "                    if (card_list[q].matching) {\n"+
        "                        payDisplay (q);\n" +
        "                        return;\n" +
        "                    }\n" +
        "                }\n" +
        "            } else {\n" +
        "                cardDisplay ();\n" +
        "            }\n" +
//        "            window.parent.postMessage ('" + PAYMENT_API_FINAL + "', window.document.referrer);\n" +
		"        }\n" +
		"    } else {\n" +
		"        bad ('Unexpected message :' + event.origin + ' ' + event.data);\n" +
		"    }\n" +
		"}\n\n" +
        "function initPayment () {\n" +
        "    if (checkNoErrors ()) {\n" +
		"        window.addEventListener('message', receiveMessage, false);\n" +
        "        checkTiming (" + PAYMENT_TIMEOUT_INIT + ");\n" +
        "        console.debug ('init payment window');\n" +
        "        window.parent.postMessage ('" + PAYMENT_API_INIT + "', window.document.referrer);\n" +
        "   }\n" +
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
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" value=\"&#x25b2;\" title=\"More\" onclick=\"updateUnits (this.form." + prod_entry + ", 1, " + temp_counter + ")\" style=\"text-align:center;margin:0px;padding:0px\" ></td>" +
					   "</tr>" +
					   "<tr>" +
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input size=\"6\" type=\"text\" name=\"" + 
					       prod_entry + 
					       "\" value=\"0\" style=\"text-align:right\" " +
					       "oninput=\"updateInput (" + temp_counter + ", this);\" autocomplete=\"off\"/></td>" +
					   "</tr>" +
					   "<tr>" +
		               "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" value=\"&#x25bc;\" title=\"Less\" onclick=\"updateUnits (this.form." + prod_entry + ", -1, " + temp_counter + ")\" style=\"text-align:center;margin:0px;padding:0px\" ></td>" +
					   "</tr>" +
					   "</table></form></td></tr>";
        temp_string.insert (0, "shopping_cart[" + temp_counter + "] = new ShopEntry (" + price_mult_100 + ");\n");		
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
        	"\nfunction checkOut () {\n" +
            "    if (getTotal ()) {\n" +
            "        shopping_enabled = false;\n" +
    		"        window.addEventListener('message', receiveMessage, false);\n" +
            "        document.getElementById ('pay').innerHTML = paycode;\n" +
            "    } else {\n" +
            "        alert ('Nothing ordered!');\n" +
            "    }\n" +
	        "}\n\n" +
		    "function getTotal () {\n" +
	        "    var total = 0;\n" +
	        "    for (var i = 0; i < shopping_cart.length; i++) {\n" +
	        "        total += shopping_cart[i].price_mult_100 * shopping_cart[i].units;\n" +
            "    }\n" +
	        "    return total;\n"+
	        "}\n\n" +
	        "function priceString (price_mult_100) {\n" +
	        "    return '$' +  Math.floor (price_mult_100 / 100) + '.' +  Math.floor((price_mult_100 % 100) / 10) +  Math.floor(price_mult_100 % 10);\n" +
	        "}\n\n" +
	        "function updateTotal () {\n" +
            "    document.getElementById ('total').innerHTML = priceString (getTotal ());\n" +
	        "}\n\n" +
	        "function updateInput (index, control) {\n" +
	        "    if (shopping_enabled) {\n" +
	        "        if (!numeric_only.test (control.value)) control.value = '0';\n" +
	        "        while (control.value.length > 1 && control.value.charAt (0) == '0') control.value = control.value.substring (1);\n" +
	        "        shopping_cart[index].units = control.value;\n" +
	        "        updateTotal ();\n" +
	        "    } else {\n" +
	        "        control.value = shopping_cart[index].units;\n" +
	        "    }\n" +
	        "}\n\n" +
            "function updateUnits (control, value, index) {\n" +
            "    control.value = parseInt (control.value) + value;\n" +
            "    updateInput (index, control);\n" +
	        "}\n\n" +
			"function receiveMessage (event) {\n" +
			"    console.debug (event.origin);\n" +
			"    console.debug (event.data);\n" +
			"    if (event.data.indexOf (payment_status)) {\n" +
			"        console.debug ('STATE ERROR: ' + event.data + '/' + payment_status);\n" +
			"        payment_status = 'Failed***';\n" +
			"        return;\n" +
			"    }\n" +
			"    var res = event.data.substring (payment_status.length);\n" +
			"    if (payment_status == '" + PAYMENT_API_INIT + "') {\n" +
			"        setTimeout(function(){\n    " +
			"        event.source.postMessage('" + PAYMENT_API_INIT + "=' + getTotal () + '");
		for (CardTypes card_type : MerchantServlet.compatible_with_merchant)
		  {
		    temp_string.append ('@')
		               .append (card_type.toString());
		  }
		temp_string.append ("', event.origin);\n" +
//			"        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
			"        }, 1000);\n" +
			"        payment_status = '" + PAYMENT_API_FINAL + "';\n" +
			"    }\n" +
			"    else if (payment_status == '" + PAYMENT_API_FINAL + "') {\n" +
            "        document.getElementById ('result').innerHTML = 'Yes!!!';\n" +
 //           "        document.getElementById ('pay').innerHTML = '';\n" +
			"    }\n" +
			"}\n");

		StringBuffer page_data = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<table>" +
               "<tr><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Merchant<br>&nbsp;</td></tr>" +
               "<tr><td id=\"result\"><table class=\"tftable\">" +
       		       "<tr><th>Image</th><th>Description</th><th>Price</th><th>Units</th></tr>" +
                   productEntry ("product-car.png", "Sports Car", 8599900) + 
                   productEntry ("product-icecream.png", "Ice Cream", 325) + 
       		       "<tr><td style=\"border-width:1px 1px 0px 0px;background:white\"></td><td style=\"text-align:center\">Total Amount</td><td style=\"text-align:right\" id=\"total\">$0.00</td><td style=\"border-width:1px 0px 0px 1px;background:white\"></td></tr>" +
               "</table></td></tr>" +
               "<tr><td style=\"text-align:center\" id=\"pay\"><input type=\"button\" value=\"Checkout..\" title=\"Paying time has come...\" onclick=\"checkOut ()\"></td></tr>" +
             "</table></td></tr>");
		temp_string.insert (0, "\nvar paycode=" + 
	            "'<iframe src=\"" + Init.bank_url + "/payment\" style=\"width:" + PAYMENT_WINDOW_WIDTH + "px;height:" + PAYMENT_WINDOW_HEIGHT + "px;border-width:1px;border-style:solid;border-color:" +
	            PAYMENT_BORDER_COLOR + ";box-shadow:3pt 3pt 3pt #D0D0D0;\"></iframe>';\n\n" +
				"var numeric_only = new RegExp ('^[0-9]{1,6}$');\n\n" +
				"var shopping_cart = [];\n" +
	            "var shopping_enabled = true;\n" +
				"var payment_status = '" + PAYMENT_API_INIT + "';\n" +
		        "ShopEntry = function (price_mult_100) {\n" +
		        "    this.price_mult_100 = price_mult_100;\n" +
		        "    this.units = 0;\n" +
		        "};\n");

        HTML.output (response, HTML.getHTML (temp_string.toString(), null, page_data.toString()));
	  }
	
	public static void initCards (HttpServletResponse response, HttpServletRequest request, Vector<CardEntry> card_entries) throws IOException, ServletException 
	  {
	    StringBuffer s = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
	        "<form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">" +
            "<table cellpadding=\"0\" cellspacing=\"5\"><tr><td></td><td style=\"text-align:center;font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Your Payment Cards<br>&nbsp;</td></tr>" +
	        "<tr><td colspan=\"2\"><table style=\"margin-left:auto;margin-right:auto\">" +
	        "<tr><td>Name</td><td><input size=\"18\" type=\"text\" maxlength=\"35\" placeholder=\"Name on the card\" name=\"" + CardEntry.USER_FIELD + "\" value=\"")
	    .append (card_entries.firstElement ().user == null ? "" : encode (card_entries.firstElement ().user))
	    .append ("\"></td></tr>" +
	        "<tr><td>PIN</td><td><input size=\"18\" type=\"text\" maxlength=\"8\" placeholder=\"Default: " + CardEntry.DEFAULT_PIN + "\" name=\"" + CardEntry.PIN_FIELD + "\" value=\"")
        .append (card_entries.firstElement ().pin == null ? "" : encode (card_entries.firstElement ().pin))
        .append ("\"></td></tr></table></td></tr>");
	    for (CardEntry card_entry : card_entries)
	      {
	        s.append ("<tr style=\"text-align:right\"><td><input type=\"checkbox\" name=\"")
	         .append (card_entry.card_type.toString ())
	         .append ("\" title=\"This card is")
	         .append (MerchantServlet.compatible_with_merchant.contains (card_entry.card_type) ? "" : " NOT")
             .append (" recognized by the demo merchant\"")
	         .append (card_entry.active ? " checked" : "")
	         .append ("></td><td>" +
	                 CardEntry.CARD_DIV_1)
	         .append (card_entry.active ? card_entry.pan : "Inactive Card")
	         .append (CardEntry.CARD_DIV_2)
	         .append (card_entry.base64_image)
	         .append ("');\"></div>" +
	                  "</td></tr>");
	      }  
	    HTML.output (response, HTML.getHTML (null, null, s.append (
	        "<tr><td></td><td style=\"text-align:center;padding:7pt\"><input type=\"submit\" value=\"Save Changes\" title=\"Cards only &quot;live&quot; in a web session\"></td></tr>" +
	        "</table></form></td></tr>").toString ()));
	  }
  }
