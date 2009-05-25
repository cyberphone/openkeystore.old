package phone;

import java.io.IOException;

import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.jce.KeyMetadataProvider;
import org.webpki.jce.KeyDescriptor;

import org.webpki.webutil.ServletUtil;

import org.webpki.crypto.CertificateInfo;


@SuppressWarnings("serial")
public class PhoneWinKeyProperties extends PhoneWinServlet
  {

    static enum KEY_PROPERTIES
      {
        KEY_TYPE          ("Key&nbsp;type",            "TDB"),
        PROVISION_DATE    ("Provision&nbsp;date",      "TDB"),
        PIN_PROTECTION    ("PIN&nbsp;protection",      "TDB"),
        CERT_PATH         ("Certificate&nbsp;path",    "TDB"),
        FRIENDLY_NAME     ("Friendly&nbsp;name",       "TDB"),
        DATABASE_ID       ("Database&nbsp;ID",         "TDB"),
        ALGORITHMS        ("Endorsed&nbsp;algorithms", "TDB"),
        PROP_BAGS         ("Property&nbsp;bags",       "TDB"),
        EXTENSIONS        ("Extension&nbsp;objects",   "TDB"),
        LOGOTYPES         ("Logotypes",                "TDB"),
        SITE_AUTO_SEL     ("Auto-select&nbsp;sites",   "TDB"),
        ARCHIVED          ("Issuer-key-backup",        "TDB"),
        EXPORTABLE        ("Exportable",               "TDB"),
        DELETE            ("Delete&nbsp;key...",       "TDB");

        private final String button_text;

        private final String help_text;
        private KEY_PROPERTIES (String button_text, String help_text)
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
        String key_id = request.getParameter ("keyid");
        KeyDescriptor kd = new KeyMetadataProvider (getUserID (session)).getKeyDescriptor (Integer.valueOf (key_id));
        if (request.getParameter ("delete") != null)
          {
            kd.deleteKey ();
            PhoneDebugWin.setDebugEvent (session, "Succeeded deleting key!");
            response.sendRedirect (ServletUtil.getContextURL (request) + "/phonewinkeyexplorer");
            return;
          }
        String disp = request.getParameter ("disp");
        String property = request.getParameter ("property");
        if (property == null)
          {
            property = KEY_PROPERTIES.values ()[0].toString ();            
          }
        StringBuffer s = createHeader ("Properties Key #" + disp).
          append ("<form method=\"GET\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><input type=\"hidden\" name=\"keyid\" value=\"").
          append (key_id).
          append ("\"><input type=\"hidden\" name=\"disp\" value=\"").
          append (disp).
          append ("\">").
          append (divSectionSelector ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">Property:</td></tr>" +
                  "<tr><td height=\"4\"></td></tr>" +
                  "<tr><td><select name=\"property\" onchange=\"submit ();\">");
        for (KEY_PROPERTIES kp : KEY_PROPERTIES.values ())
          {
            s.append ("<option ");
            if (kp == KEY_PROPERTIES.DELETE)
              {
                s.append ("style=\"background-color:#FFC0C0\" ");
              }
            if (kp.toString ().equals (property))
              {
                s.append ("selected ");
              }
            s.append ("value=\"").
              append (kp.toString ()).
              append ("\">").
              append (kp.getButtonText ());
          }
        s.append ("</select></td></tr></table></div>").
          append (divSectionSelection ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">");
        switch (KEY_PROPERTIES.valueOf (property))
          {
            case KEY_TYPE:
              s.append (kd.isSymmetric () ? "Symmetric Key" : "PKI [X.509]");
              break;

            case ARCHIVED:
              s.append (kd.isSymmetric () ? "This is a shared key" : 
                              (kd.isArchived () ? "The issuer also has a copy of this key in order to unlock encrypted data after a loss of the original key" :                                                  "Only you have the private key"));
              break;

            case EXPORTABLE:
              s.append (kd.isExportable () ? "This key may be exported" : "This key cannot be exported");
              break;

            case PROVISION_DATE:
              s.append (kd.getProvisioningDate ());
              break;

            case DATABASE_ID:
              s.append ("USERKEYS.KeyID=").append (key_id);
              break;

            case PIN_PROTECTION:
              if (kd.isPINProtected ())
                {
                  s.append ("PIN format: ").
                    append (kd.getPINFormat ().toString ());
                }
              else
                {
                  s.append ("Not PIN protected");
                }
              break;

            case ALGORITHMS:
              if (kd.isSymmetric ())
                {
                  if (kd.getSupportedAlgorithms () == null)
                    {
                      s.append ("&lt;Unrestricted&gt;");
                    }
                  else
                    {
                      printURIs (s, kd.getSupportedAlgorithms ());
                    }
                }
              else
                {
                  s.append ("RSA");
                }
              break;

            case FRIENDLY_NAME:
              s.append (kd.getFriendlyName () == null ? "N/A" : kd.getFriendlyName ());
              break;

            case DELETE:
              s.append ("Note that deleting a key is an <i>irreversible</i> operation!</td></tr>" +
                        "<tr><td height=\"10\"></td></tr>" +
                        "<tr><td align=\"center\"><input type=\"submit\" name=\"delete\" value=\"Delete\">");
              break;

            case CERT_PATH:
              X509Certificate[] cert_path = kd.getCertificatePath ();
              int i = cert_path.length;
              while (--i >= 0)
                {
                  s.append ("<a href=\"phonewincertprops?keyid=").
                    append (key_id).
                    append ("&cert=").
                    append (i).
                    append ("&disp=").
                    append (disp).
                    append ("&device=false\">CN=").
                    append (new CertificateInfo (cert_path[i]).getSubjectCommonName ()).
                    append ("</a>");
                  if (i > 0)
                    {
                      s.append ("<br><center>\u2193</center>");
                    }
                }
              break;

            default:
              s.append ("Not Implemented Yet!");
          }
        s.append ("</td></tr></table></div></form>").
          append (createFooter ("phonewinkeyexplorer"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
