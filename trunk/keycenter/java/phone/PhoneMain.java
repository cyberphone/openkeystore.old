package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class PhoneMain extends ProtectedServlet
  {
    static final int PHONE_IMAGE_WIDTH = 300;
    static final int PHONE_LEFT_MARGIN = 15;
    static final int DEBUG_WIN_LEFT_MARGIN = PHONE_IMAGE_WIDTH + PHONE_LEFT_MARGIN + 20;
    static final int RIGHT_MARGIN = 28;
    static final int TOP_MARGIN = 20;
    static final int SCREEN_OFFSET_TOP = 90;
    static final int SCREEN_OFFSET_LEFT = 30;
    static final int SCREEN_TOP = TOP_MARGIN + SCREEN_OFFSET_TOP;
    static final int SCREEN_LEFT = PHONE_LEFT_MARGIN + SCREEN_OFFSET_LEFT;
    static final int BOTTOM_MARGIN = 20;

    static final int DEBUG_WIN_BORDER = 2;
    static final String DEBUG_WIN_BORDER_COLOR = "#B0B0B0";

    static final int PHONE_WIN_BORDER = 2;
    static final String PHONE_WIN_BORDER_COLOR = "#808080";

    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.PHONE_LAUNCH;
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head><link rel=\"shortcut icon\" href=\"k2.ico\">" +
            "<title>Mobile Phone Emulator - ").
          append (getEmailAddress (request)).
          append ("</title>" +
            "<style type=\"text/css\">html {overflow:hidden} " +
            GENERIC_STYLE +
            "</style>" +
            "<script type=\"text/javascript\">\n" +
            "var xmlhttp;\n" +
            "window.onresize = function ()\n" +
            "{\n" +
            "  sizecomponents ();\n" +
            "}\n" +
            "function goit ()\n" +
            "{\n" +
            "  if (xmlhttp.readyState == 4)\n" +
            "    {\n" +
            "      if (xmlhttp.status == 200 && xmlhttp.responseText == '<yes/>')\n" +
            "        {\n" +
            "          window.frames['debugwin'].document.location.reload (true);\n" +
            "        }\n" +
            "      oneround ();\n"+
            "    }\n" +
            "}\n" +
            "function oneround ()\n" +
            "{\n" +
            "  for (;;) try\n" +
            "    {\n" +
            "      if (window.XMLHttpRequest)\n" +
            "        {\n" +
            "          xmlhttp = new XMLHttpRequest ();\n" +
            "        }\n" +
            "      else\n" +
            "        {\n" +
            "          xmlhttp = new ActiveXObject ('Microsoft.XMLHTTP');\n" +
            "        }\n" +
            "      xmlhttp.open ('GET', '" + ServletUtil.getContextURL (request) + "/phoneajaxhandler', true);\n" +
            "      xmlhttp.setRequestHeader('If-Modified-Since', 'Sat, 1 Jan 2000 00:00:00 GMT');\n" +
            "      xmlhttp.onreadystatechange = goit;\n" +
            "      xmlhttp.send (null);\n" +
            "      break;\n" +
            "    }\n" +
            "  catch (e) { }\n" +
            "}\n" +
            "function chk4neg (value)\n" +
            "{\n" +
            "  return (value < 20 ? 20 : value) + 'px';\n" +
            "}\n" +
            "function initdialog ()\n" +
            "{\n" +
            "  sizecomponents ();\n" +
            "  oneround ();\n"+
            "}\n" +
            "function sizecomponents ()\n" +
            "{\n" +
            "  if (document.all == null) // FF, Opera, etc\n" +
            "    {\n" +
            "      document.getElementById ('debugwin').style.width = (window.innerWidth - " +
                      (DEBUG_WIN_LEFT_MARGIN + RIGHT_MARGIN) + ") + 'px';\n" +
            "      document.getElementById ('debugwin').style.height = (window.innerHeight - " +
                      (TOP_MARGIN + BOTTOM_MARGIN) + ") + 'px';\n" +
            "    }\n" +
            "  else // MSIE 6+\n" +
            "    {\n" +
            "      document.all.debugwin.style.width = chk4neg (document.body.offsetWidth - " +
                       (DEBUG_WIN_LEFT_MARGIN + RIGHT_MARGIN) + ");\n" +
            "      document.all.debugwin.style.height = chk4neg (document.body.offsetHeight - " +
                       (TOP_MARGIN + BOTTOM_MARGIN) + ");\n" +
            "    }\n" +
            "}\n" +
            "</script>" +

            "</head><body onload=\"initdialog ()\">" +
            "<img src=\"images/myphone.gif\" style=\"position:absolute;top:" + TOP_MARGIN + "px;left:" + PHONE_LEFT_MARGIN + "px\">" +
            "<a href=\"phonewinhome\" title=\"Home sweet home...\" target=\"mobwin\" style=\"z-index:7;visibility:visible;position:absolute;top:" +
            (SCREEN_TOP + PhoneWinServlet.SCREEN_HEIGHT + 20) + "px;left:" + (PHONE_LEFT_MARGIN + 115) + "px\"><img src=\"images/btn_home.gif\" border=\"0\"></a>" +
            "<iframe frameborder=\"0\" style=\"z-index:7;visibility:visible;position:absolute;top:" + SCREEN_TOP +
            "px;left:" + SCREEN_LEFT + "px;border-width:0px;margin:0px;padding:0px\" height=\"").
    append (PhoneWinServlet.SCREEN_HEIGHT).
    append ("\" name=\"mobwin\" scrolling=\"auto\" src=\"phonewinhome\" width=\"").
    append (PhoneWinServlet.SCREEN_WIDTH).
    append ("\"></iframe>" +
            "<!--[if IE]>" +
            "<table cellpadding=\"" + DEBUG_WIN_BORDER + "\" cellspacing=\"0\" style=\"background-color:" +
            DEBUG_WIN_BORDER_COLOR + ";position:absolute;top:" + TOP_MARGIN + "px;left:" + DEBUG_WIN_LEFT_MARGIN + "px\"><tr><td>" +
            "<iframe height=800 id=\"debugwin\" name=\"debugwin\" scrolling=auto src=\"phonedebugwin#last\" width=600 marginheight=0 marginwidth=0 frameborder=0></iframe>" +
            "</td></tr></table>" +
            "<![endif]-->" +
            "<![if !IE]>" +
            "<iframe style=\"position:absolute;top:" + TOP_MARGIN + "px;left:" + DEBUG_WIN_LEFT_MARGIN + "px;border-color:" +
            DEBUG_WIN_BORDER_COLOR + ";border-style:solid;border-width:" +
                   DEBUG_WIN_BORDER + "px\" height=800 id=\"debugwin\" name=\"debugwin\" scrolling=auto src=\"phonedebugwin#last\" width=600 marginheight=0 marginwidth=0></iframe>" +
            "<![endif]>" +
            "</body></html>");

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
