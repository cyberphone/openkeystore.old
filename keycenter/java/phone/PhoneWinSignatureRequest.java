package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinSignatureRequest extends PhoneWinServlet
  {
static final String sreq = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html style=\"overflow:auto\"><head><style type=\"text/css\">" +
"html, body {margin: 0px; padding: 0px; height: 100%} " +
"body {font-size: 10px; color: #000000; font-family: Verdana, Arial; background-color: #ffffff} " +
"td {font-size: 10px; font-family: Verdana, Arial} " +
".headline {font-weight: bolder; font-size: 12px; font-family: Arial, Verdana} " +
"</style></head><body><table border=\"0\" cellpadding=\"2\" cellspacing=\"0\" width=\"100%\" height=\"100%\"><tr><td align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td align=\"center\"><img src=\"images/egovernment.gif\"></td></tr><tr><td height=\"5\"></td></tr><tr><td align=\"center\" class=\"headline\">Income declaration</td></tr><tr><td height=\"5\"></td></tr><tr><td align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\"><tr><td align=\"right\">Year:&nbsp;</td><td align=\"left\"><b>2007</b></td></tr><tr><td align=\"right\">Name:&nbsp;</td><td align=\"left\"><b>Shuji Nakamura</b></td></tr><tr><td align=\"right\">Citizen&nbsp;code:&nbsp;</td><td align=\"left\"><b>19470226-1022</b></td></tr><tr><td align=\"right\">Declared&nbsp;income:&nbsp;</td><td align=\"left\"><b>$1000-$4999</b></td></tr></table></td></tr></table></td></tr></table></body></html>";

    String createIframeWithBorder (int top, int width, int height, String url)
      {
        int left = (SCREEN_WIDTH - width) / 2;
        StringBuffer s = new StringBuffer ("<iframe id=\"theshow\" name=\"theshow\" frameborder=\"0\" " +
                  "style=\"z-index:10;visibility:visible;position:absolute;top:").
                  append (top + 1).
                  append ("px;left:").
                  append (left + 1).
                  append ("px;width:").
                  append (width - 2).
                  append ("px;height:").
                  append (height - 2).
                  append ("px;border-width:0px;background-color:white\" src=\"").
                  append (url).
                  append ("\"></iframe><div id=\"theborder\" style=\"z-index:7;visibility:visible;position:absolute;top:").
                  append (top).
                  append ("px;left:").
                  append (left).
                  append ("px;width:").
                  append (width).
                  append ("px;height:").
                  append (height).
                  append ("px;border-style:none;background-color:#000000;\"></div>");
        return s.toString ();
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        PhoneWinResource.clearResourceList (session);
        String url = PhoneWinResource.addResource (session, sreq.getBytes ("UTF-8"), "text/html");

        StringBuffer s = createHeader ("Signature Request").
          append (createIframeWithBorder (40, SCREEN_WIDTH - 4, SCREEN_HEIGHT - 40 - 120, url)).
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
