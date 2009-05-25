package phone;

import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.ImageData;
import org.webpki.webutil.ServletUtil;

import org.webpki.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.PassphraseFormats;

import org.webpki.jce.Provisioning;
import org.webpki.jce.PINProvisioning;
import org.webpki.jce.Logotype;


@SuppressWarnings("serial")
public class PhoneWinKeyGen2Init extends PhoneWinServlet
  {
    private static final String PROV_STATE = "PROV_STATE";

    static class ProvisioningState
      {
        PINProvisioning pin_provisioning;
        KeyOperationRequestDecoder keyopreq_decoder;
        X509Certificate keyopreq_server_certificate;
        PlatformNegotiationRequestDecoder platform_decoder;        PlatformNegotiationResponseEncoder platform_encoder;      }

    static ProvisioningState getProvisioningState (HttpSession session) throws IOException
      {
        return (ProvisioningState)session.getAttribute (PROV_STATE);
      }

    private void addLogotypeAndFooter (StringBuffer s, HttpSession session, KeyOperationRequestDecoder keyop_decoder) throws IOException
      {
        ImageData logotype = keyop_decoder.getIssuerLogotype ();
        if (logotype == null)
          {
            logotype = Logotype.getDefaultLogotype (KeyGen2URIs.LOGOTYPES.APPLICATION);
          }
        PhoneWinResource.clearResourceList (session);
        s.append (divSection (50, 110)).
          append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td style=\"border-width:1px;border-style:solid;border-color:black\"><img src=\"").
          append (PhoneWinResource.addResource (session, logotype.getData (), logotype.getMimeType ())).
          append ("\" style=\"padding:10px\" title=\"Issuer logotype\"></td>").
          append (verticalShaddow (2)).
          append ("</tr><tr>").
          append (horizontalShaddow (1)).
          append ("</tr></table></div></form>").
          append (createFooter ("phonewinapps"));
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ProvisioningState ps = getProvisioningState (session);
        String pin = request.getParameter ("pin");
        String error = null;
        if (ps.pin_provisioning.next ())
          {
            if (pin != null)
              {
                if (ps.pin_provisioning.verify ())
                  {
                    error = ps.pin_provisioning.setVerify (pin);
                  }
                else
                  {
                    error = ps.pin_provisioning.setValue (pin);
                  }
              }
          }
        if (ps.pin_provisioning.next ())
          {
            StringBuffer s = createHeader ("Key Generation - " + (ps.pin_provisioning.verify () ? "Verify PIN" : "Set PIN")).
              append ("<form name=\"shoot\" method=\"POST\" action=\"").
              append (request.getRequestURL ().toString ()).
              append ("\">").

              append (divSection (160, 30)).
              append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                      "<tr><td align=\"center\">");
            if (ps.pin_provisioning.verify ())
              {
                s.append  ("&nbsp;<br>Verify the previously set PIN");
              }
            else
              {
                s.append ("Set a new PIN<br><i>(").
                  append (ps.pin_provisioning.getMinLength ()).
                  append ('-').
                  append (ps.pin_provisioning.getMaxLength ()).
                  append (' ').
                  append (ps.pin_provisioning.getFormat () == PassphraseFormats.NUMERIC ?
                              "digits" : ps.pin_provisioning.getFormat ().getXMLName ()).
                  append (")</i>");
              }
            s.append ("</td></tr></table></div>");

            addPINDialog (s, ps.pin_provisioning.getFormat (), error, true);

            /*======================================================*/
            /* In this aplication we always show a logotype.        */
            /*======================================================*/
            addLogotypeAndFooter (s, session, ps.keyopreq_decoder);

            setHTMLMode (response);
            response.getOutputStream ().print (s.toString ());
          }
        else
          {
            StringBuffer s = createHeader ("Key Generation - Execute",
                                           null,
                                           "document.location.href = '" + ServletUtil.getContextURL (request) + "/phonewinkg2generate'").
              append (divSection (100, 150)).
              append ("<table align=\"center\" cellpadding=\"5\" cellspacing=\"0\">" +
                      "<tr><td align=\"center\">Please wait while keys are being processed...</td></tr>" +
                      "<tr><td height=\"20\"></td></tr>" +
                      "<tr><td align=\"center\"><img src=\"images/animatedkey.gif\" title=\"Cryptokeys - The movie!\"></td></tr>" +
                      "</table></div>").
              append (createFooter ());

            setHTMLMode (response);
            response.getOutputStream ().print (s.toString ());
          }
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ProvisioningState ps = new ProvisioningState ();
        PhoneUtil.setDeferredCertificationHandler (session, null);        PlatformNegotiationRequestDecoder platform_decoder = (PlatformNegotiationRequestDecoder)PhoneUtil.getXMLObject (session);        PlatformNegotiationResponseEncoder platform_encoder =
            new Provisioning (getUserID (session)).negotiate (platform_decoder);
        if (PhoneUtil.writeXMLObject (session, request, response, platform_encoder, platform_decoder.getSubmitURL ()))
          {
            System.out.println ("There was presumably a KG2 platform error");
            return;
          }
        KeyOperationRequestDecoder keyopreq_decoder = (KeyOperationRequestDecoder)PhoneUtil.getXMLObject (session);
        ps.keyopreq_server_certificate = PhoneUtil.getServerCertificate (session);
        ps.keyopreq_decoder = keyopreq_decoder;
        ps.platform_decoder = platform_decoder;
        ps.platform_encoder = platform_encoder;
        ps.pin_provisioning = new PINProvisioning (keyopreq_decoder);
        session.setAttribute (PROV_STATE, ps);

        StringBuffer s = createHeader ("Key Generation - Init").
          append ("<form name=\"shoot\" method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\">").

          append (divSection (160, SCREEN_HEIGHT)).
          append ("<table align=\"center\" cellpadding=\"5\" cellspacing=\"0\">" +
                  "<tr><td>The provider above wants to issue a new key or update keys that it has " +
                  "previously issued.</td></tr>" +
                  "<tr><td height=\"5\"></td></tr>" +
                  "<tr><td align=\"center\"><input type=\"button\" value=\"" +
                  "Continue\" onclick=\"this.disabled=true;document.forms.shoot.submit()\"></td></tr></table></div>");

        /*======================================================*/
        /* In this aplication we always show a logotype.        */
        /*======================================================*/
        addLogotypeAndFooter (s, session, keyopreq_decoder);

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
