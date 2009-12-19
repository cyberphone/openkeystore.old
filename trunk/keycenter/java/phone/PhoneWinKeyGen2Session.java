package phone;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.PassphraseFormats;

import org.webpki.sks.PINProvisioning;


@SuppressWarnings("serial")
public class PhoneWinKeyGen2Session extends PhoneWinKeyGen2Base
  {

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
            /* In this application we always show a logotype.       */
            /*======================================================*/
            addLogotypeAndFooter (s, session, ps.platform_decoder);

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
        ProvisioningState ps = getProvisioningState (session);
        if (PhoneUtil.writeXMLObject (session, request, response, ps.platform_encoder, ps.platform_decoder.getSubmitURL ()))
          {
            System.out.println ("There was presumably a KG2 platform error");
            return;
          }
        KeyOperationRequestDecoder keyopreq_decoder = (KeyOperationRequestDecoder)PhoneUtil.getXMLObject (session);
        ps.keyopreq_server_certificate = PhoneUtil.getServerCertificate (session);
        ps.keyopreq_decoder = keyopreq_decoder;
        ps.pin_provisioning = new PINProvisioning (keyopreq_decoder);
        protectedPost (request, response, session);
      }
  }
