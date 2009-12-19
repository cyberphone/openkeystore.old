package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.sks.OTPProvider;
import org.webpki.sks.ExtensionProvider;
import org.webpki.sks.InformationCardProvider;
import org.webpki.sks.KeyMetadataProvider;
import org.webpki.sks.KeyDescriptor;


@SuppressWarnings("serial")
public class PhoneWinKeyExplorer extends PhoneWinServlet
  {

    String getTD (int i, KeyDescriptor[] kds, boolean last_right)
      {
        StringBuffer td = new StringBuffer ("<td align=\"center\" style=\"padding:1px;border-width:0px ").
          append (last_right ? 1 : 0).
          append ("px ").
          append (i == kds.length ? 1 : 0).
          append ("px 1px;border-style:solid;border-color:black");
        if (i == 1)
          {
            td.append (";padding-top:2px"); 
          }
        if (i == kds.length)
          {
            td.append (";padding-bottom:2px"); 
          }
        return td.append ("\">").toString ();
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        KeyDescriptor[] kds = new KeyMetadataProvider (getSKS (session)).getKeyDescriptors ();
        StringBuffer s = createHeader ("Key Explorer").
          append (divSection ()).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\"><tr>" +
                  "<td align=\"center\" style=\"padding:2px;border-width:1px 0px 1px 1px;border-style:solid;border-color:black;background-color:#E0E0E0\">&nbsp;#&nbsp;</td>" +
                  "<td align=\"center\" style=\"padding:2px;border-width:1px 0px 1px 1px;border-style:solid;border-color:black;background-color:#E0E0E0\">&nbsp;Type&nbsp;</td>" +
                  "<td align=\"center\" style=\"padding:2px;border-width:1px 0px 1px 1px;border-style:solid;border-color:black;background-color:#E0E0E0\">&nbsp;Extension&nbsp;</td>" +
                  "<td align=\"center\" style=\"padding:2px;border-width:1px 1px 1px 1px;border-style:solid;border-color:black;background-color:#E0E0E0\">&nbsp;PIN&nbsp;</td>").
          append (verticalShaddow ((kds.length == 0 ? 1 : kds.length) + 2)).
          append ("</tr>");
        int i = 0;
        for (KeyDescriptor kd : kds)
          {
            String td1 = getTD (++i, kds, false);
            String td2 = getTD (i, kds, true);
            s.append ("<tr bgcolor=\"ivory\">").
              append (td1).
              append ("<a href=\"phonewinkeyprops?keyid=").
              append (kd.getKeyID ()).
              append ("&disp=").
              append (i).
              append ("\" title=\"").
              append (kd.getFriendlyName ()).
              append ("\">&nbsp;").
              append (i).
              append ("&nbsp;</a></td>").
              append (td1).
              append (kd.isSymmetric () ? "Sym" : "PKI").
              append ("</td>").
              append (td1);
            if (kd.isSymmetric ())
              {
                s.append (OTPProvider.getOTPProvider (kd.getKeyID (), getSKS (session)) == null  ? "&nbsp;" : "OTP");
              }
            else
              {
                ExtensionProvider ep = ExtensionProvider.getExtensionProvider (kd.getKeyID (), getSKS (session));
                if (ep != null && ep instanceof InformationCardProvider)
                  {
                    s.append ("InfoCard");
                  }
                else
                  {
                    s.append ("&nbsp;");
                  }
              }
            s.append ("</td>").
              append (td2).
              append (kd.isPINProtected () ?
                               kd.isPINLocked () ?
                      "<a href=\"phonewinkeyunlock?keyid=" + kd.getKeyID () + "&disp=" + i + "\"><font color=\"red\">PUK</font></a>"
                                                 :
                                      "OK" : "N/A").
              append ("</td></tr>");
          }
        if (kds.length == 0)
          {
            s.append ("<tr bgcolor=\"ivory\"><td colspan=\"4\" align=\"center\" " +
                      "style=\"padding:2px;border-width:0px 1px 1px 1px;border-style:solid;border-color:black\">" +
                      "You have no keys</td></tr>");
          }
        s.append ("<tr>").
          append (horizontalShaddow (4)).
          append ("</tr></table></div>").
          append (createFooter ("phonewinsecurity"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
