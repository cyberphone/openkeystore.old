/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

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

	
    static final String HTML_INIT = 
	    "<!DOCTYPE html>"+
	    "<html><head><link rel=\"shortcut icon\" href=\"favicon.ico\">"+
        "<meta name=\"viewport\" content=\"initial-scale=1.0\"/>" +
	    "<title>JSON Signature Demo</title>"+
	    "<style type=\"text/css\">html {overflow:auto} html, body {margin:0px;padding:0px;height:100%} "+
	    "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white} "+
	    "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica} "+
	    "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica} "+
	    "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} "+
	    "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} "+
	    "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana} "+
	    "input {font-weight:normal;font-size:8pt;font-family:verdana,arial} "+
	    "td {font-size:8pt;font-family:verdana,arial} "+
	    ".smalltext {font-size:6pt;font-family:verdana,arial} "+
	    "button {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px} "+
	    ".headline {font-weight:bolder;font-size:10pt;font-family:arial,verdana} "+
	    ".dbTR {border-width:1px 1px 1px 0;border-style:solid;border-color:black;padding:4px} "+
	    ".dbTL {border-width:1px 1px 1px 1px;border-style:solid;border-color:black;padding:4px} "+
	    ".dbNL {border-width:0 1px 1px 1px;border-style:solid;border-color:black;padding:4px} "+
	    ".dbNR {border-width:0 1px 1px 0;border-style:solid;border-color:black;padding:4px} "+
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
        s.append ("><a href=\"http://primekey.se\" title=\"PrimeKey Solutions\" style=\"position:absolute;top:15px;left:15px;z-index:5;visibility:visible\">" + "<img src=\"images/logotype.png\" border=\"0\"></a>" + "<table cellapdding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\">").append (box).append ("</table></body></html>");
        return s.toString ();
      }
    
    private static void output (HttpServletResponse response, String html) throws IOException, ServletException
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


    public static void homePage (HttpServletResponse response, String baseurl) throws IOException, ServletException
      {
        String request_url =  baseurl + "/request";
        HTML.output (response, HTML.getHTML (null,
                null,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width=\"300px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JCS Home - JSON Clear Text Signature<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"center\"><a href=\"" + baseurl + "/verify\">Verify a JCS with a browser</a></td></tr>" +
                   "<tr><td align=\"center\">&nbsp;</td></tr>" +
                   "<tr><td align=\"center\"><a href=\"" + baseurl + "/create\">Create a JCS</a></td></tr>" +
                   "<tr><td align=\"center\">&nbsp;</td></tr>" +
                   "<tr><td align=\"center\">Invoke <a href=\"" + request_url + "\">" + request_url + "</a> for JCS testing with a client device</td></tr>" +
                 "</table></td></td>"));
      }

    public static void verifyPage (HttpServletResponse response, HttpServletRequest request, String signature) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
                HOME,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table><form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">"  +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Testing JSON Signatures<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">Paste a JSON signature in the text box or try with the default:</td></tr>" +
                   "<tr><td align=\"left\"><textarea rows=\"20\" cols=\"100\" maxlength=\"3000\" name=\"" + RequestServlet.JCS_ARGUMENT + "\">" + encode (signature) + "</textarea></td></tr>" +
                   "<tr><td align=\"center\">&nbsp;<br><input type=\"submit\" value=\"Verify JSON Signature!\" name=\"sumbit\"></td></tr>" +
                 "</form></table></td></td>"));
      }

    public static void errorPage (HttpServletResponse response, String error) throws IOException, ServletException
      {
        HTML.output (response, HTML.getHTML (null,
              HOME,
                "<tr><td width=\"100%\" align=\"center\" valign=\"middle\">" +
                "<table style=\"max-width=\"300px\">" +
                   "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana;color:red\">Something went wrong...<br>&nbsp;</td></tr>" +
                   "<tr><td align=\"left\">" + newLines2HTML (encode (error)) + "</td></tr>" +
                 "</table></td></td>"));
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
            "<table><form method=\"POST\" action=\"" + request.getRequestURL ().toString () + "\">"  +
               "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">JSON Signature Creation<br>&nbsp;</td></tr>" +
               "<tr><td align=\"left\">Arbitrary data that you want to sign:</td></tr>" +
               "<tr><td align=\"left\"><textarea rows=\"10\" cols=\"50\"  maxlength=\"200\" name=\"" + CreateServlet.MY_DATA_TO_BE_SIGNED + "\"></textarea></td></tr>" +
               "<tr><td align=\"center\"><table>" +
                 "<tr><td valign=\"middle\" rowspan=\"3\">Select signing key:&nbsp;</td><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + MySignature.ACTION.SYM + 
                 "\">Symmetric key</td><td>" +
                 "<tr><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + MySignature.ACTION.ASYM + "\" checked=\"checked\">EC Key (P-256)</td><td>" +
                 "<tr><td align=\"left\"><input type=\"radio\" name=\"" + CreateServlet.KEY_TYPE + "\" value=\"" + MySignature.ACTION.X509 + "\">X.509 Certificate/Private key</td><td>" +
                 "</table></td></tr>" +
               "<tr><td align=\"center\">&nbsp;<br><input type=\"submit\" value=\"Create JSON Signature!\" name=\"sumbit\"></td></tr>" +
             "</form></table></td></td>"));
      }
  }
