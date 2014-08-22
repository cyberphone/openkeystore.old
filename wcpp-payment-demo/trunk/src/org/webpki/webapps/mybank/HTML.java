package org.webpki.webapps.mybank;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

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
                                      "  &quot;Statement&quot;: &quot;Hello signed world!&quot;,\n" +
                                      "  &quot;OtherProperties&quot;: [2000, true]\n" +
                                      "}";
    
    static final int PAYMENT_WINDOW_WIDTH           = 300;
    static final int PAYMENT_WINDOW_HEIGHT          = 300;
    static final int PAYMENT_LOADING_SIZE           = 48;
    static final int PAYMENT_DIV_HORIZONTAL_PADDING = 6;
    static final int PAYMENT_DIV_VERTICAL_PADDING   = 5;

    static final int PAYMENT_TIMEOUT_INIT           = 5000;
    
    static final String PAYMENT_API_INIT             = "INIT";
	
    static final String HTML_INIT = 
	    "<!DOCTYPE html>"+
	    "<html><head><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
//        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
	    "<title>WebCrypto++ Bank Demo</title>"+
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

    public static String fancyBox (String id, String content)
      {
        return "<div id=\"" + id + "\" style=\"" + STATIC_BOX + COMMON_BOX + "\">" + content + "</div>";
      }

    public static void homePage (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width=\"300px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">WebCrypto++ Payment Demo<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a href=\"" + Init.bank_url + "/initcards\">Initialize payment cards</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a href=\"" + Init.merchant1_url + "\">Go to Merchant #1</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a href=\"" + Init.merchant2_url + "\">Go to Merchant #2</a></td></tr>" +
                   "<tr><td>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\"><a target=\"_blank\" href=\"http://webpki.org/papers/PKI/pki-webcrypto.pdf\">WebCrypto++ Documentation</a></td></tr>" +
                 "</table></td></tr>"));
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
            "<!DOCTYPE html>\n<html><head><title>WebCrypto/JCS Demo</title></head>\n" +
            "<body style=\"padding:10pt;font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white\">\n" +
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
              "function fancyDiv (header, content)\n" +
              "{\n" +
              "  return header + ':<br><div style=\"margin-top:3pt;background:#F8F8F8;border-width:1px;border-style:solid;border-color:grey;\\\n" + 
              "         max-width:800pt;padding:10pt;word-wrap:break-word;box-shadow:3pt 3pt 3pt #D0D0D0\">' + content + '</div>';\n" +
              "}\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Error message helper                                                 //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
             "function bad (id, message)\n" +
              "{\n" +
              "  document.getElementById (id).innerHTML = '<b style=\"color:red\">' + message + '</b>';\n" +
              "}\n\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "// Create key event handler                                             //\n" +
              "//////////////////////////////////////////////////////////////////////////\n" +
              "function createKey ()\n" +
              "{\n" +
              "  console.log ('Begin creating key...');\n" +
              "  document.getElementById ('pub.key').innerHTML = '<i>Working...</i>';\n")
            .append (msie_flag ?
               "  var genOp = crypto.subtle.generateKey ({name: \"RSASSA-PKCS1-v1_5\", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n" +
               "                                         false,\n" +
               "                                         [\"sign\", \"verify\"]);\n\n" +
               "  genOp.onerror = function (e)\n" +
               "    {\n" +
               "      bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
               "    }\n\n" +

               "  genOp.oncomplete = function (e)\n" +
               "    {\n" +
               "      pubKey = e.target.result.publicKey;\n" +
               "      privKey = e.target.result.privateKey;\n\n" +

               "      var expOp = crypto.subtle.exportKey ('spki', pubKey);\n\n" +

               "      expOp.onerror = function (e)\n" +
               "        {\n" + 
               "          bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
               "        }\n\n" +

               "      expOp.oncomplete = function (evt)\n" +
               "        {\n" +
               "          publicKeyInX509Format = new Uint8Array (evt.target.result);\n" +
               "          console.log ('generateKey() RSASSA-PKCS1-v1_5: PASS');\n" +
               webCryptoGenerateJS () +
               "        }\n\n" +
               "    }" 
                  : 
               "  crypto.subtle.generateKey ({name: \"RSASSA-PKCS1-v1_5\", hash: {name: \"SHA-256\"}, modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01])},\n" +
               "                               false,\n" +
               "                               [\"sign\", \"verify\"]).then (function (key)\n" +
               "    {\n" +
               "      pubKey = key.publicKey;\n" +
               "      privKey = key.privateKey;\n\n" +

               "      crypto.subtle.exportKey ('spki', pubKey).then (function (key)\n" +
               "        {\n" +
               "          publicKeyInX509Format = new Uint8Array (key);\n" +
               "          console.log ('generateKey() RSASSA-PKCS1-v1_5: PASS');\n" +
               webCryptoGenerateJS () +
               "        });\n" +
               "    }).then (undefined, function ()\n" + 
               "    {\n" + 
               "      bad ('pub.key', 'WebCrypto failed for unknown reasons');\n" +
               "    });");
        html.append ("\n}\n\n" +
               "//////////////////////////////////////////////////////////////////////////\n" +
               "// JCS callback functions                                               //\n" +
               "//////////////////////////////////////////////////////////////////////////\n" +
               "var JCSSigner = function ()\n" +
               "{\n" +
               "};\n\n" +

               "/* String */ JCSSigner.prototype.getAlgorithm = function ()\n" +
               "{\n" +
               "  // Every crypto-system with some self-estem defines their own algorithm IDs, right?\n" +
               "  return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';\n" +
               "};\n\n" +

               "/* JSONSignatureTypes */JCSSigner.prototype.getSignatureType = function ()\n" +
               "{\n" +
               "  return org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY;\n" +
               "};\n\n" +

               "/* Uint8Array */ JCSSigner.prototype.getPublicKey = function ()\n" +
               "{\n" +
               "  return publicKeyInX509Format;\n" +
               "};\n\n" +
               "//////////////////////////////////////////////////////////////////////////\n" +
               "// Sign event handler                                                   //\n" +
               "//////////////////////////////////////////////////////////////////////////\n" +
               "function signSampleData ()\n" +
               "{\n" +
               "  try\n" +
               "    {\n" +
               "      signatureWriter = new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse (document.getElementById ('json.text').value));\n" +
               "    }\n" +
               "  catch (err)\n" +
               "    {\n" +
               "      bad ('sign.res', 'JSON error: ' + err.toString ());\n" +
               "      return;\n" +
               "    }\n\n")
 
          .append (msie_flag ?
              "  var signer = crypto.subtle.sign ({name: \"RSASSA-PKCS1-v1_5\",\n" +
              "                                    hash: \"SHA-256\"},\n" +
              "                                    privKey,\n" +
              "                                    signatureWriter.beginSignature (new JCSSigner ()));\n\n" +

              "  signer.onerror = function (evt)\n" +
              "    {\n" +
              "      bad ('sign.res', 'WebCrypto failed for unknown reasons');\n" +
              "    }\n\n" +

              "  signer.oncomplete = function (evt)\n" +
              "    {\n" +
              "      var signatureValue = new Uint8Array (evt.target.result);\n" +
              "      console.log ('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n" +
              outputSignature () +
              "    }" 
                :
              "  crypto.subtle.sign ({name: \"RSASSA-PKCS1-v1_5\"},\n" +
              "                      privKey,\n" +
              "                      signatureWriter.beginSignature (new JCSSigner ())).then (function (signature)\n" +
              "    {\n" +
              "      var signatureValue = new Uint8Array (signature);\n" +
              "      console.log ('Sign with RSASSA-PKCS1-v1_5 - SHA-256: PASS');\n" +
              outputSignature () +
              "    }).then (undefined, function ()\n" + 
              "    {\n" +
              "      bad ('sign.res', 'WebCrypto failed for unknown reasons');\n" +
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
            "function verifySignatureOnServer ()\n" +
            "{\n" +
            "  document.location.href = '" + verify_base + "' +\n" +
            "      org.webpki.util.Base64URL.encode (org.webpki.util.ByteArray.convertStringToUTF8 (signatureWriter.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED)));\n" +
            "}\n";
      }

    private static String outputSignature ()
      {
        return "      document.getElementById ('sign.res').innerHTML = fancyDiv ('Signed data in JCS format',\n" +
               "          signatureWriter.endSignature (signatureValue).serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_HTML)) +\n" +
//               "          '<p><input type=\"button\" value=\"Verify Signature (on the server)\" onClick=\"document.location.href=\\'" + verify_base + "\\'' +\n" +
//               "          org.webpki.util.Base64URL.encode (org.webpki.util.ByteArray.convertStringToUTF8 (signatureWriter.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED))) + '; return false\"></p>';\n";
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

    public static void browserCheck (HttpServletResponse response) throws IOException, ServletException
      {
        HTML.output (response, "<!DOCTYPE html><html><head><title>WebCrypto and JCS Demo</title>" +
        "</head><body style=\"padding:10pt;font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white\">Finding browser..." +
        "<script>\n" +
        " var d = new Date();\n" +
        " d.setTime(d.getTime()+(60*60*1000));\n" +
        "if (window.crypto !== undefined && window.crypto.subtle !== undefined)\n" +
        "{\n" +
        " console.log ('WebCrypto Support');\n" +
        " document.cookie = '" + WebCryptoServlet.BROWSER_COOKIE + "=" + WebCryptoServlet.STD + "; expires=' + d.toGMTString();\n" +
        "}\n" +
        "else if (window.crypto === undefined && window.msCrypto !== undefined)\n" +
        "{\n" +
        " console.log ('MSIE 11');\n" +
        " document.cookie = '" + WebCryptoServlet.BROWSER_COOKIE + "=" + WebCryptoServlet.MSIE + "; expires=' + d.toGMTString();\n" +
        "}\n" +
        "document.location.reload ();\n" + 
        "</script></body></html>");
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
        "</style></head><body onload=\"initPayment ()\"><div style=\"color:white;font-size:10pt;background:blue;width:" + (PAYMENT_WINDOW_WIDTH - (PAYMENT_DIV_HORIZONTAL_PADDING * 2)) +"px\">Payment Request</div><div id=\"main\">Initializing...</div>" +
        "<img id=\"busy\" src=\"images/loading.gif\" style=\"position:absolute;top:" + ((PAYMENT_WINDOW_HEIGHT - PAYMENT_LOADING_SIZE) / 2) + "px;left:" + ((PAYMENT_WINDOW_WIDTH - PAYMENT_LOADING_SIZE) / 2) + "px;z-index:5;visibility:visible;\"/>" +
        "<script type=\"text/javascript\">\n" +
        "var aborted_operation = false;\n" +
        "var timeouter_handle = null;\n" +
        "var payment_state = '" + PAYMENT_API_INIT + "';\n" +
        "function bad (message) {\n" +
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
		"function receiveMessage (event) {\n" +
		"    console.debug (event.origin);\n" +
		"    console.debug (event.data);\n" +
		"    if (aborted_operation) return;\n" +
		"    if (timeouter_handle) {\n" +
		"        clearTimeout (timeouter_handle);\n" +
		"        timeouter_handle = null;\n" +
		"        var res = checkState (event)\n" +
		"        if (!res) return;\n" +
		"        console.debug ('Argument: ' + res);\n" +
        "        document.getElementById ('busy').style.visibility = 'hidden';\n" +
		"        if (payment_state == '" + PAYMENT_API_INIT + "') {\n" +
        "            document.getElementById ('main').innerHTML='Payment Received!'\n" +
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
		String s = "<tr style=\"text-align:center\"><td><img src=\"" + image_url +
				   "\"></td><td>" + name + "</td><td style=\"text-align:right\">" + price  (price_mult_100) +
				   "</td><td><form>" +
					   "<table style=\"border-width:0px;padding:0px;margin:0px;border-spacing:2px;border-collapse:separate\">" +
					   "<tr>" +
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"button\" value=\"&#x25b2;\" title=\"More\" onclick=\"updateUnits (this.form." + prod_entry + ", 1, " + temp_counter + ")\" style=\"text-align:center;margin:0px;padding:0px\" ></td>" +
					   "</tr>" +
					   "<tr>" +
					   "<td style=\"border-width:0px;padding:0px;margin:0px\"><input type=\"text\" name=\"" + 
					       prod_entry + 
					       "\" value=\"0\" style=\"text-align:right;width:30pt;\" " +
					       "oninput=\"updateInput (" + temp_counter + ", this);\" " +
					       "onkeypress=\"return isNumberKey (event);\"/></td>" +
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
	
	private static String imageURL (String main_path, ServletContext context) throws IOException
	  {
		return "data:image/png;base64," +
            new Base64 (false).getBase64StringFromBinary (ArrayUtil.getByteArrayFromInputStream (context.getResourceAsStream ("/images/" + main_path)));		
	  }

	public static void merchantPage (HttpServletResponse response, ServletContext context) throws IOException, ServletException
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
	        "function isNumberKey (evt) {\n" +
		    "    var charCode = (evt.which) ? evt.which : evt.keyCode;\n" +
		    "    return !(charCode > 31 && (charCode < 48 || charCode > 57));\n" +
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
	        "        shopping_cart[index].units = control.value;\n" +
	        "        updateTotal ();\n" +
	        "    }\n" +
	        "}\n\n" +
            "function updateUnits (control, value, index) {\n" +
	        "    if (parseInt (control.value) + value >= 0 && shopping_enabled) {\n" +
            "        control.value = parseInt (control.value) + value;\n" +
            "        shopping_cart[index].units = parseInt (control.value);\n" +
	        "        updateTotal ();\n" +
            "    }\n" +
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
			"        setTimeout(function(){\n" +
			"        event.source.postMessage('" + PAYMENT_API_INIT + "=' + getTotal (), event.origin);\n" +
//			"        }, " + (PAYMENT_TIMEOUT_INIT + 1000) + ");\n" +
			"        }, 1000);\n" +
			"    }\n" +
			"}\n");

		StringBuffer page_data = new StringBuffer (
            "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
            "<table>" +
               "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Merchant<br>&nbsp;</td></tr>" +
               "<tr><td><table class=\"tftable\">" +
       		       "<tr><th>Image</th><th>Description</th><th>Price</th><th>Units</th></tr>" +
                   productEntry (imageURL ("product-car.png", context), "Sports Car", 8599900) + 
                   productEntry (imageURL ("product-icecream.png", context), "Ice Cream", 325) + 
       		       "<tr><td style=\"border-width:1px 1px 0px 0px;background:white\"></td><td style=\"text-align:center\">Total Amount</td><td style=\"text-align:right\" id=\"total\">$0.00</td><td style=\"border-width:1px 0px 0px 1px;ound:white\"></td></tr>" +
               "</table></td></tr>" +
               "<tr><td align=\"center\" id=\"pay\"><input type=\"button\" value=\"Checkout..\" title=\"Paying time has come...\" onclick=\"checkOut ()\"></td></tr>" +
             "</table></td></tr>");
		temp_string.insert (0, "\nvar paycode=" + 
	            "'<iframe src=\"" + Init.bank_url + "/payment\" style=\"width:" + PAYMENT_WINDOW_WIDTH + "px;height:" + PAYMENT_WINDOW_HEIGHT + "px;border-width:1px;border-style:solid;border-color:blue;box-shadow:3pt 3pt 3pt #D0D0D0;\"></iframe>';\n\n" +
				"var shopping_cart = [];\n" +
	            "var shopping_enabled = true;\n" +
				"var payment_status = '" + PAYMENT_API_INIT + "';\n" +
		        "ShopEntry = function (price_mult_100) {\n" +
		        "    this.price_mult_100 = price_mult_100;\n" +
		        "    this.units = 0;\n" +
		        "};\n");

        HTML.output (response, HTML.getHTML (temp_string.toString(), null, page_data.toString()));
	  }
  }
