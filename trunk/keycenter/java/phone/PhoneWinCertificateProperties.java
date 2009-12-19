package phone;

import java.io.IOException;

import java.util.Date;
import java.util.TimeZone;
import java.text.SimpleDateFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.CertificateInfo;

import org.webpki.util.Base64;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.sks.KeyMetadataProvider;
import org.webpki.sks.SecureKeyStore;


@SuppressWarnings("serial")
public class PhoneWinCertificateProperties extends PhoneWinServlet
  {
    enum CERT_PROPERTIES
      {
        SUBJECT             ("Subject&nbsp;DN",              "TDB"),
        ISSUER              ("Issuer&nbsp;DN",               "TDB"),
        VALID_FROM          ("Valid&nbsp;from",              "TDB"),
        VALID_TO            ("Valid&nbsp;to",                "TDB"),
        SERIAL              ("Serial&nbsp;number",           "TDB"),
        BASIC_CONSTRAINTS   ("Basic&nbsp;constraints",       "TDB"),
        KEY_USAGE           ("Key&nbsp;usage",               "TDB"),
        EXT_KEY_USAGE       ("Extended&nbsp;key&nbsp;usage", "TDB"),
        POLICY_OIDS         ("Policy&nbsp;key&nbsp;OIDs",    "TDB"),
        AIA_CA_ISSUERS      ("AIA&nbsp;CA&nbsp;issuers",     "TDB"),
        AIA_OCSP_RESP       ("OCSP&nbsp;responders",         "TDB"),
        PUBLIC_KEY          ("Public&nbsp;key",              "TDB"),
        FINGERPRINT         ("SHA1&nbsp;fingerprint",        "TDB"),
        EXPORT              ("Export&nbsp;certificate",      "TDB");

        private final String button_text;

        private final String help_text;
        private CERT_PROPERTIES (String button_text, String help_text)
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


    private String niceDate (Date date)
      {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        sdf.setTimeZone (TimeZone.getTimeZone ("UTC"));
        return sdf.format (date);
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String key_id = request.getParameter ("keyid");
        String cert = request.getParameter ("cert");
        String disp = request.getParameter ("disp");
        String device = request.getParameter ("device");
        boolean dev_flag = new Boolean (device);
        SecureKeyStore sks = getSKS (session);
        CertificateInfo cert_info = new CertificateInfo ((
           dev_flag ?
             sks.getDeviceCertificatePath ()
                    :
             new KeyMetadataProvider (sks).getKeyDescriptor (Integer.valueOf (key_id)).getCertificatePath ()
                                                        )[Integer.valueOf (cert)]);
        String property = request.getParameter ("property");
        if (property == null)
          {
            property = CERT_PROPERTIES.values ()[0].toString ();            
          }
        StringBuffer s = createHeader ("Certificate Properties").
          append ("<form method=\"GET\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><input type=\"hidden\" name=\"keyid\" value=\"").
          append (key_id).
          append ("\"><input type=\"hidden\" name=\"cert\" value=\"").
          append (cert).
          append ("\"><input type=\"hidden\" name=\"disp\" value=\"").
          append (disp).
          append ("\"><input type=\"hidden\" name=\"device\" value=\"").
          append (device).
          append ("\">").
          append (divSectionSelector ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">Property:</td></tr>" +
                  "<tr><td height=\"4\"></td></tr>" +
                  "<tr><td><select name=\"property\" onchange=\"submit ();\">");
        for (CERT_PROPERTIES cp : CERT_PROPERTIES.values ())
          {
            s.append ("<option ");
            if (cp == CERT_PROPERTIES.EXPORT)
              {
                s.append ("style=\"background-color:#FFC0C0\" ");
              }
            if (cp.toString ().equals (property))
              {
                s.append ("selected ");
              }
            s.append ("value=\"").
              append (cp.toString ()).
              append ("\">").
              append (cp.getButtonText ());
          }
        s.append ("</select></td></tr></table></div>").
          append (divSectionSelection ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">");
        switch (CERT_PROPERTIES.valueOf (property))
          {
            case SUBJECT:
              s.append (cert_info.getSubject ());
              break;

            case ISSUER:
              s.append (cert_info.getIssuer ());
              break;

            case SERIAL:
              s.append (cert_info.getSerialNumber ()).
                append ("<br>(0x").
                append (cert_info.getSerialNumberInHex ()).
                append (")");
              break;

            case FINGERPRINT:
              s.append ("<code>").
                append (ArrayUtil.toHexString (cert_info.getCertificateHash (), 0, -1, true, ' ')).
                append ("</code>");
              break;

            case POLICY_OIDS:
              printURIs (s, cert_info.getPolicyOIDs ());
              break;

            case AIA_CA_ISSUERS:
              printURIs (s, cert_info.getAIACAIssuers ());
              break;

            case AIA_OCSP_RESP:
              printURIs (s, cert_info.getAIAOCSPResponders ());
              break;

            case VALID_FROM:
              s.append (niceDate (cert_info.getNotBeforeDate ()));
              break;

            case VALID_TO:
              s.append (niceDate (cert_info.getNotAfterDate ()));
              break;

            case KEY_USAGE:
              printURIs (s, cert_info.getKeyUsages ());
              break;

            case EXT_KEY_USAGE:
              printURIs (s, cert_info.getExtendedKeyUsage ());
              break;

            case BASIC_CONSTRAINTS:
              String bc = cert_info.getBasicConstraints ();
              s.append (bc == null ? UNSPECIFIED : bc);
              break;

            case PUBLIC_KEY:
              s.append (cert_info.getPublicKeyAlgorithm ()).
                append (" (").
                append (cert_info.getPublicKeySize ()).
                append (" bit)<pre style=\"margin-top:5px;margin-bottom:0px;font-size:10px\">").
                append (DebugFormatter.getHexDebugData (cert_info.getPublicKeyData (), -8)).
                append ("</pre>");
              break;

            case EXPORT:
              s.append ("<input type=\"button\" value=\"Download..\" " +
                        "onclick=\"shoot.certblob.value='").
                append (new Base64 (false).getBase64StringFromBinary (cert_info.getCertificateBlob ())).
                append ("';shoot.submit ()\">");
              break;
          }
        s.append ("</td></tr></table></div></form><form name=\"shoot\" method=\"POST\" action=\"certviewer\">" +
                  "<input type=\"hidden\" name=\"certblob\"></form>").
          append (createFooter (dev_flag ?
                                "phonewinseproperties" 
                                         :
                                "phonewinkeyprops?keyid=" + key_id + "&disp=" + disp + "&property=" + 
                                   PhoneWinKeyProperties.KEY_PROPERTIES.CERT_PATH.toString ()));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
