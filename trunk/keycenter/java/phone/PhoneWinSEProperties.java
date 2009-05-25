package phone;

import java.io.IOException;

import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.crypto.CertificateInfo;

import org.webpki.jce.crypto.CryptoDriver;
import org.webpki.jce.KeyUtil;


@SuppressWarnings("serial")
public class PhoneWinSEProperties extends PhoneWinServlet
  {

    static enum SE_PROPERTIES
      {
        NAME              ("Name&nbsp;&amp;&nbsp;identification",  "TDB"),
        CERTIFICATE       ("Device&nbsp;certificate",            "TDB"),
        ALGORITHMS        ("Supported&nbsp;algorithms",          "TDB");

        private final String button_text;

        private final String help_text;
        private SE_PROPERTIES (String button_text, String help_text)
          {
            this.button_text = button_text;
            this.help_text = help_text;
          }


        public String getButtonText ()
          {
            return button_text;
          }


        public String getHelpText ()
          {
            return help_text;
          }

      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String property = request.getParameter ("property");
        if (property == null)
          {
            property = SE_PROPERTIES.values ()[0].toString ();            
          }
        StringBuffer s = createHeader ("Security Element").
          append ("<form method=\"GET\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\">").
          append (divSectionSelector ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">Property:</td></tr>" +
                  "<tr><td height=\"4\"></td></tr>" +
                  "<tr><td><select name=\"property\" onchange=\"submit ();\">");
        for (SE_PROPERTIES se_prop : SE_PROPERTIES.values ())
          {
            s.append ("<option ");
            if (se_prop.toString ().equals (property))
              {
                s.append ("selected ");
              }
            s.append ("value=\"").
              append (se_prop.toString ()).
              append ("\">").
              append (se_prop.getButtonText ());
          }
        s.append ("</select></td></tr></table></div>").
          append (divSectionSelection ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">");
        switch (SE_PROPERTIES.valueOf (property))
          {
            case NAME:
              byte[] cert_hash = new CertificateInfo (new CryptoDriver (getUserID (session)).getDeviceCertificatePath ()[0]).getCertificateHash ();
              String dev_id = ArrayUtil.toHexString (cert_hash, 0, -1, true, ' ');
              String string_rep = new StringBuffer ().
                append (dev_id.substring (0, 29)).
                append ('\n').
                append (dev_id.substring (30)).
                append ("\n#").
                append (DebugFormatter.getHexString (KeyUtil.getCRC16 (cert_hash))).toString ();
              s.append (CryptoDriver.getDeviceName ());
              s.append ("</td></tr><tr><td height=\"15\"></td></tr><tr><td align=\"center\">" +
                        "<table cellpadding=\"0\" cellspacing=\"0\">" +
                        "<tr>" +
                        "<td align=\"center\" style=\"border-width:1px 1px 1px 1px;border-style:solid;border-color:black;padding:4px;background-color:#E0E0E0\">Device Fingerprint</td>" +
                        "<td rowspan=\"3\" background=\"images/vshaddow.gif\" width=\"2\"></td></tr>" +
                        "<tr bgcolor=\"ivory\">" +
                        "<td align=\"left\" style=\"border-width:0 1px 1px 1px;border-style:solid;border-color:black;padding:4px\"><pre style=\"margin:0px;padding:0px\">").
                append (string_rep).
                append ("</pre></td>" +
                        "</tr><tr><td background=\"images/hshaddow.gif\" height=\"2\"></td></tr>" +
                        "</table></td></tr><tr><td height=\"10\"></td></tr><tr><td align=\"center\">" +
                        "<input value=\"Send fingerprint...\" type=\"button\" onclick=\"location.href='phonewinsendmail?msg=").
                append (URLEncoder.encode (string_rep, "UTF-8")).
                append ("'\">");
              break;

            case ALGORITHMS:
              printURIs (s, CryptoDriver.getSupportedAlgorithms ());
              break;

            case CERTIFICATE:
              response.sendRedirect (ServletUtil.getContextURL (request) + "/phonewincertprops?device=true&cert=0");
              return;

            default:
              s.append ("Not Implemented Yet!");
          }
        s.append ("</td></tr></table></div></form>").
          append (createFooter ("phonewinsecurity"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
