package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.keygen2.KeyOperationResponseEncoder;
import org.webpki.keygen2.KeyOperationRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestDecoder;
import org.webpki.keygen2.CredentialDeploymentResponseEncoder;

import user.UserResetAccount;

import org.webpki.sks.Provisioning;


@SuppressWarnings("serial")
public class PhoneWinKeyGen2Generate extends PhoneWinKeyGen2Base
  {
    class LocalDebug implements Provisioning.DebugCallback
      {
        HttpSession session;
        LocalDebug (HttpSession session)
          {
            this.session = session;
          }
        public void print (String message) throws IOException
          {
            PhoneDebugWin.setDebugEvent (session, message);
          }
      }

    private void oneCred (StringBuffer s, String name, String image, String javascript, String title)
      {
        s.append ("<tr valign=\"middle\"><td align=\"right\">").
          append (name).
          append ("&nbsp;</td><td><img src=\"images/").
          append (image).
          append (".png\" onclick=\"").
          append (javascript).
          append ("\" style=\"cursor:pointer\" title=\"").
          append (title).
          append ("\"></td></tr>");
      }

    void deployAndFinish (HttpServletRequest request,                          HttpServletResponse response,                          HttpSession session,                          Provisioning provisioning,                          KeyOperationRequestDecoder keyopreq_decoder)
    throws Exception      {        CredentialDeploymentRequestDecoder credep_decoder = (CredentialDeploymentRequestDecoder)PhoneUtil.getXMLObject (session);
        provisioning.finalizeProvisioning (credep_decoder, keyopreq_decoder);        CredentialDeploymentResponseEncoder success_encoder = 
                    new CredentialDeploymentResponseEncoder (credep_decoder.getClientSessionID (),
                                                             credep_decoder.getServerSessionID ());
        boolean standard = session.getAttribute (QUICK_RUN) == null;
        if (!PhoneUtil.writeXMLObject (session, request, standard ? response : null, success_encoder, credep_decoder.getSubmitURL ()))
          {
            if (standard)
              {
                bad ("KG2 state error during CDRE");
              }
            else
              {
                UserResetAccount.clearOTPCounters (session);
                PhoneDebugWin.setDebugEvent (session, "OTP counters were reset");
                StringBuffer s = createHeader ("QuickRun - Step #2", PhoneWinOTP.LAUNCH_BANK_OTP_JS).
                  append (divSection (40, 300)).
                  append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                          "<tr><td>Success!<br>&nbsp;<br>Now you can try logging on using one of the just provisioned credentials by clicking on it.</td></tr>" +
                          "<tr><td height=\"10\"></td></tr>" +
                          "<tr><td align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\">");
                oneCred (s, "OTP&nbsp;Token", 
                            "qr_otp",
                            PhoneWinOTP.getLaunchBankOTPLoginURL (request, session),
                            "Login using the phone as a token and the PC browser as channel");
                s.append ("<tr><td height=\"12\" colspan=\"2\"></td></tr>");
                oneCred (s, "Information&nbsp;Card", 
                            "qr_infocard",
                            "alert ('Sorry, only OTP login is currently implemented')",
                            "Login to a federated site using the mobile browser");
                s.append ("<tr><td height=\"12\" colspan=\"2\"></td></tr>");
                oneCred (s, "Digital&nbsp;Certificate",
                            "qr_certificate",
                            "alert ('Sorry, only OTP login is currently implemented')",
                            "Login to MyBank using PKI and the mobile browser");
                s.append ("</table></td></tr></table></div>").
                  append (createFooter ());

                setHTMLMode (response);
                response.getOutputStream ().print (s.toString ());
              }
          }      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        Provisioning provisioning = new Provisioning (getSKS(session), new LocalDebug (session));
        ProvisioningState ps = getProvisioningState (session);

        try
          {
            KeyOperationResponseEncoder encoder =
                provisioning.initializeProvisioning (ps.keyopreq_decoder,
                                                     ps.platform_decoder,                                                     ps.platform_encoder,
                                                     ps.pin_provisioning,
                                                     ps.keyopreq_server_certificate);
            if (PhoneUtil.writeXMLObject (session, request, response, encoder, ps.keyopreq_decoder.getSubmitURL ()))
              {                if (ps.keyopreq_decoder.getDeferredCertificationFlag ())                  {                    PhoneUtil.setDeferredCertificationHandler (session, "phonewinkg2delayedgenerate");                    return;                  }
                bad ("There was presumably a KG2 keyopres error");
              }
            deployAndFinish (request, response, session, provisioning, ps.keyopreq_decoder);
          }
        catch (Exception e)
          {
            internalPhoneError (response, e);
            provisioning.cleanupFailedProvisioning (ps.keyopreq_decoder);
          }
      }

  }
