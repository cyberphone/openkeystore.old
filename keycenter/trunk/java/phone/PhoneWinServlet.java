package phone;

import java.io.IOException;

import java.security.Security;
import java.security.Provider;

import java.util.ServiceLoader;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.sks.KeyDescriptor;

import org.webpki.keygen2.PassphraseFormats;

import org.webpki.sks.Registry;
import org.webpki.sks.JCEProvider;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.SetupProperties;

import misc.ProtectedServlet;

import misc.KeyCenterCommands;

@SuppressWarnings("serial")
public abstract class PhoneWinServlet extends ProtectedServlet
  {
    static final String UNSPECIFIED = "&lt;unspecified&gt;";
    
    static final int SCREEN_WIDTH = 240;

    static final int SCREEN_HEIGHT = 320;

    static final int PIN_DIALOG_TOP = 210;

    static final int COMMAND_BUTTON_MARGIN = 26;

    static final String QUICK_RUN = "QUICK_RUN";

    public static String serial_port;
    
    public static int baud_rate;
    
    protected KeyCenterCommands getCommand ()
      {
        return null;
      }

    protected void setQuickRunFlag (HttpSession session, String arg_or_null)
      {
        session.setAttribute (QUICK_RUN, arg_or_null);
      }

    protected StringBuffer createHeader (String header, String javascript, String onload_arg)
      {
        StringBuffer s = new StringBuffer ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head>" +
            "<style type=\"text/css\">html {overflow:hidden} " +
            "html, body {margin:0px;padding:0px} " +
            "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white} " +
            "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica} " +
            "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica} " +
            "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} " +
            "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} " +
            "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana} " +
            "input {font-weight:normal;font-size:8pt;font-family:verdana,arial} " +
            "select {font-weight:normal;font-size:8pt;font-family:verdana,arial} " +
            "td {font-size:8pt;font-family:verdana,arial} " +
            ".smalltext {font-size:6pt;font-family:verdana,arial} " +
            "button {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px} " +
            ".headline {font-weight:bolder;font-size:10pt;font-family:arial,verdana} " +
            "</style>");
        if (javascript != null)
          {
            s.append ("<script type=\"text/javascript\">\n").
              append (javascript).
              append ("</script>");
          }
        s.append ("</head><body style=\"background-image:url(images/menuheader.gif);background-repeat:repeat-x\"");
        if (onload_arg == null)
          {
            s.append ('>');
          }
        else
          {
            s.append (" onload=\"").append (onload_arg).append ("\">");
          }
        s.append ("<table style=\"margin:0px;padding:0px;position:absolute;top:0px;width:" + SCREEN_WIDTH +
                  "px;left:0px;height:26px\"><tr><td align=\"center\" valign=\"middle\"><b>").
          append (header).
          append ("</b></td></tr></table>");
        return s;
      }


    protected StringBuffer createHeader (String header, String javascript)
      {
        return createHeader (header, javascript, onLoadArgument ());
      }


    protected StringBuffer createHeader (String header)
      {
        return createHeader (header, (String) null);
      }

    protected void internalPhoneError (HttpServletResponse response, String message) throws IOException, ServletException
      {
        StringBuffer s = createHeader ("*** INTERNAL ERROR ***").
          append (divSection ()).
          append ("<table><tr><td>").
          append (message).
          append ("</td></tr>" +
                  "</table></div>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

    protected void internalPhoneError (HttpServletResponse response, Exception e) throws IOException, ServletException
      {        String error = e.getMessage ();        if (error == null)          {
            error = "Missing error";          }
        StringBuffer s = new StringBuffer (error).append ("<br>");
        for (StackTraceElement ste : e.getStackTrace())
          {
            s.append (ste.toString ()).append ("<br>");
          }
        internalPhoneError (response, s.toString ());
      }


    String divSection (int top, int height)
      {
        if (freeBaseArea () > SCREEN_HEIGHT - height - top)
          {
            height = SCREEN_HEIGHT - top - freeBaseArea ();
          }
        StringBuffer s = new StringBuffer ("<div style=\"z-index:7;visibility:visible;overflow:auto" +
                  ";position:absolute;top:").
          append (top).
          append ("px;left:0px;width:" + (SCREEN_WIDTH - 8) + "px;height:").
          append (height).
          append ("px;border-style:none;padding-left:4px;padding-right:4px\">");
        return s.toString ();
      }


    int freeBaseArea ()
      {
        return COMMAND_BUTTON_MARGIN;
      }


    String divSection ()
      {
        return divSection (50, SCREEN_HEIGHT);
      }


    String divSectionSelector ()
      {
        return divSection (50, 50);
      }


    String divSectionSelection ()
      {
        return divSection (100, SCREEN_HEIGHT);
      }


    private static String localAttentionDialog (String message, String image, String background_color, boolean dismiss_button)
      {
        StringBuffer s = new StringBuffer ("<table cellpadding=\"0\" cellspacing=\"0\"><tr>" +
                  "<td style=\"padding-left:4px;background-color:").
          append (background_color).
          append (";border-width: 1px 0 1px 1px; border-color: black; border-style: solid\"><img src=\"images/").
          append (image).
          append ("\"></td><td align=\"left\" style=\"padding:6pt;background-color:").
          append (background_color).
          append (";border-width: 1px ").
          append (dismiss_button ? "0" : "1px").
          append (" 1px 0; border-color: black; border-style: solid\">").
          append (message).
          append ("</td>");
        if (dismiss_button)
          {
            s.append ("<td valign=\"top\" align=\"right\" style=\"padding:1px;background-color:").
              append (background_color).
              append (";border-width: 1px 1px 1px 0; border-color: black; border-style: solid\">" +
                      "<a href=\"javascript:dismissattention ()\" title=\"Close this dialog\"><img src=\"images/dialog-x.gif\" border=\"0\"></a></td>");
          }
        s.append (verticalShaddow (1)).
          append ("</tr><tr>").
          append (horizontalShaddow (dismiss_button ? 4 : 3)).
          append ("</tr></table>");
        return s.toString ();
      }


    public static String infoMessage (String message, boolean dismiss_button)
      {
        return localAttentionDialog (message, "i.gif", COLOR_INACTIVE, dismiss_button);
      }


    public static String errorMessage (String message, boolean dismiss_button)
      {
        return localAttentionDialog (message, "exclmark.gif", COLOR_ACTIVE, dismiss_button);
      }


    void addPINDialog (StringBuffer s, PassphraseFormats format, String error, boolean x_mark)
      {
        if (error != null)
          {
            s.append ("<script type=\"text/javascript\">\n" +
                      "function dismissattention ()\n" +
                      "{\n" +
                      "  if (document.all == null) // FF, Opera, etc\n" +
                      "    {\n" +
                      "      document.getElementById ('pinproblem').style.visibility = 'hidden';\n" +
                      "    }\n" +
                      "  else // MSIE 6+\n" +
                      "    {\n" +
                      "      document.all.pinproblem.style.visibility = 'hidden';\n" +
                      "    }\n" +
                      "}\n" +
                      "</script>" +
                      "<div id=\"pinproblem\" style=\"background-image:url(images/semi.gif);z-index:10;visibility:visible" +
                      ";position:absolute;top:" + (PIN_DIALOG_TOP - 10) +
                      "px;left:0px;width:" + (SCREEN_WIDTH - 8) + "px;height:" +
                      (SCREEN_HEIGHT - PIN_DIALOG_TOP - COMMAND_BUTTON_MARGIN + 20) +
                      "px;border-style:none;padding-left:4px;padding-right:4px\">" +
                      "<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                      "<tr><td height=\"35\"></td></tr><tr><td align=\"center\">").
              append (errorMessage (error, x_mark)).
              append ("</td></tr></table></div>");
          }
        s.append ("<script type=\"text/javascript\">\n" +
                  "function addpindigit (n)\n" +
                  "{\n" +
                  "  document.forms.shoot.pin.value = document.forms.shoot.pin.value + n;\n" +
                  "}\n" +
                  "function delpindigit ()\n" +
                  "{\n" +
                  "  var l = document.forms.shoot.pin.value.length;\n" +
                  "  if (l > 0) document.forms.shoot.pin.value = document.forms.shoot.pin.value.substring (0, l - 1);\n" +
                  "}\n" +
                  "</script>").
          append (divSection (PIN_DIALOG_TOP, SCREEN_HEIGHT)).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr valign=\"middle\">" +
                  "<td>PIN&nbsp;</td><td><input type=\"password\" size=\"20\" name=\"pin\"></td>" +
                  "</tr></table></td></tr>");
        if (format == PassphraseFormats.NUMERIC)
          {
            s.append ("<tr><td height=\"10\"></td></tr>" +
                      "<tr><td align=\"center\"><img src=\"images/numpinkbd.gif\" border=\"0\" usemap=\"#pinkbdmap\">" +
                      "<map name=\"pinkbdmap\">");
            for (int i = 0; i < 10 ; i++)
              {
                int y1 = i < 5 ? 0 : 27;
                int x1 = (i % 5) * 28;
                s.append ("<area shape=\"rect\" coords=\"").
                  append (x1).
                  append (',').
                  append (y1).
                  append (',').
                  append (x1 + 19).
                  append (',').
                  append (y1 + 18).
                  append ("\" href=\"javascript:addpindigit('").
                  append (i).
                  append ("')\" title=\"Digit #").
                  append (i).
                  append ("\">");
              }
            s.append ("<area shape=\"rect\" coords=\"146,0,165,18\" href=\"javascript:delpindigit()\" title=\"Delete last digit\">" +
                      "<area shape=\"poly\" coords=\"146,28,176,28,176,0,195,0,195,46,146,46\" href=\"javascript:document.forms[0].submit()\" title=\"Enter PIN\">" +
                      "</map></td></tr>");
         }
        else
          {
            s.append ("<tr><td height=\"10\"></td></tr><tr><td align=\"center\">" +
                      "Non-numeric PIN &#x00bb; Use keyboard..." +
                      "</td></tr><tr><td height=\"10\"></td></tr>" +
                      "<tr><td align=\"center\"><input type=\"submit\" value=\"" +
                      "Enter\"></td></tr>");
          }
        s.append ("</table></div>");
      }


    void addPINDialog (StringBuffer s, KeyDescriptor kd, boolean pin_failure)
      {
        boolean pin_locked = kd.isPINLocked ();
        boolean bad_pin_mode = kd.isInBadPINMode ();
        String error = null;
        if (pin_locked || pin_failure || bad_pin_mode)
          {
            if (pin_locked)
              {
                error = "Key has been <i>Locked!</i><br>Unlock it with <a href=\"phonewinkeyexplorer\">Key Explorer</a>";
              }
            else
              {
                String pin_word = pin_failure ? "" : " PIN";
                error = (pin_failure ? "Incorrect PIN!<br>" :"") + 
                           ((kd.numberOfPINAttemptsLeft () == 1) ?
                              "<i>Last" + pin_word + " attempt...</i>"
                                    :
                              kd.numberOfPINAttemptsLeft () + pin_word + " tries left");
              }
          }
        addPINDialog (s, kd.getPINFormat (), error, !pin_locked);
      }


   String phoneAppHeader (String header, int deviation)
      {
        return "<table width=\"100%\" cellspacing=\"0\" border=\"0\" style=\"margin:0px;padding:0px\">" +
               "<tr><td height=\"18\" valign=\"middle\" align=\"center\" style=\"margin:0px;padding:0px\"><b>" + header +
               "</b></td></tr><tr><td height=\"" +
               (12 + deviation) + "\"></td></tr>";
      }


    String phoneAppHeader (String header)
      {
        return phoneAppHeader (header, 0);
      }


    protected String makeBreakingLine (String line)
      {
        StringBuffer s = new StringBuffer ("<span style=\"font-family:'Lucida Sans Unicode',verdana,arial\">");
        char br = line.startsWith ("http") ? '/' : line.startsWith ("urn:") ? ':' : '.'; 
        for (int i = 0; i < line.length (); i++)
          {
            char c = line.charAt (i);
            s.append (c);
            if (c == br && i < line.length () - 1)
              {
                s.append ("&#8203;");
              }
          }
        return s.append ("</span>").toString ();
      }


    protected void printURIs (StringBuffer s, String[] inuris) throws IOException
      {
        if (inuris == null)
          {
            s.append (UNSPECIFIED);
          }
        else
          {
            boolean break_it = false;
            for (String uri : inuris)
              {
                if (break_it)
                  {
                   s.append ("</td></tr>");
                   if (uri.length () > 20 || uri.indexOf (':') > 0)
                     {
                       s.append ("<tr><td height=\"5\"></td></tr><tr><td align=\"left\">");
                     }
                   s.append ("<tr><td align=\"left\">");
                  }
                else
                  {
                    break_it = true;
                  }
                s.append (makeBreakingLine (uri));
              }
          }
      }


    protected String createFooter (String return_url)
      {
        return "<a href=\"" + return_url + "\" style=\"position:absolute;top:4px;left:2px;z-index:5;visibility:visible\">" +
               "<img src=\"images/phoneleftarrow.gif\" title=\"&quot;I'll be back!&quot;\" border=\"0\"></a></body></html>";
      }
    protected String createFooter ()
      {
        return "</body></html>";
      }


    public static boolean internalApps (ServletContext context) throws IOException
      {
        return new Boolean (context.getInitParameter ("phone-internal-apps"));
      }


    public static SecureKeyStore getSKS (HttpSession session) throws IOException
      {
        SecureKeyStore sks = ServiceLoader.load (SecureKeyStore.class).iterator ().next ();
        if (sks instanceof SetupProperties)
          {
            SetupProperties setup = (SetupProperties) sks;
            for (String prop : setup.getProperties ())
              {
                if (prop.equalsIgnoreCase ("userid"))
                  {
                    setup.setProperty (prop, String.valueOf (getUserID (session)));
                  }
              }
            setup.init ();
          }
        return sks;
      }

    public static void initPhone (ServletContext context) throws IOException
      {
        serial_port = context.getInitParameter ("serial-port");
        baud_rate = Integer.parseInt (context.getInitParameter ("baudrate"));
        Registry.fakeinit ();
        if (internalApps (context))
          {
            Provider prov = new JCEProvider ();
            if (Security.getProvider (prov.getName ()) == null)
              {
                Security.addProvider (prov);
              }
          }
      }
  }
