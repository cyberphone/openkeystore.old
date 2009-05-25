package misc;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.DebugFormatter;

import org.webpki.webutil.ServletUtil;

import org.webpki.keygen2.KeyGen2Constants;


@SuppressWarnings("serial")
public class MiscResources extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.RESOURCES;
      }

    void doclink (StringBuffer s, String url, String description, boolean restricted)
      {
        s.append ("<tr><td><a href=\"javascript:viewdoc ('").
          append (url).append ("')\">").
          append (description).
          append ("</a>");
        if (restricted)
          {
            s.append ("&nbsp;&nbsp;<img src=\"images/lock.gif\" title=\"Restricted access\">");
          }
        s.append ("</td></tr>");
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        boolean restricted = RestrictedMode.isRestricted (request, response, getServletContext ());
        String baseurl = ServletUtil.getContextURL (request);
        if (baseurl.startsWith ("https"))
          {
            baseurl = "http" + baseurl.substring (5);
          }

        StringBuffer s = createHeader (request,
         "function viewdoc (url)\n{\nwindow.open (url,'_blank','resizable=yes,scrollbars=yes,toolbar=no,menubar=yes,location=no,status=no');\n}\n").
          append ("<table><tr><td align=\"center\" class=\"headline\">Resources and Documention<br>&nbsp;</td></tr>");
        doclink (s, baseurl + "/keygen2-short-presentation.pdf", "Short Presentation", false);
        doclink (s, baseurl + "/schemaviewer/" + DebugFormatter.getHexString (KeyGen2Constants.KEYGEN2_NS.getBytes ("UTF-8")), "KeyGen2 XML Schema", restricted);
        doclink (s, baseurl + "/javadoc/library", "WebPKI.org Java Library", false);
        doclink (s, baseurl + "/javadoc/keystore/org/webpki/jce/crypto/VirtualSE.html", "Virtual Security Element", false);
        doclink (s, baseurl + "/universal-keystore-database.pdf", "Core Database Schema", false);
        s.append ("</table></td></tr></table>").append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
