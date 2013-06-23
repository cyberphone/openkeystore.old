package phone;

import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpSession;

import org.webpki.util.ImageData;
import org.webpki.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.sks.PINProvisioning;
import org.webpki.sks.Logotype;


@SuppressWarnings("serial")
public abstract class PhoneWinKeyGen2Base extends PhoneWinServlet
  {
    static final String PROV_STATE = "PROV_STATE";

    static class ProvisioningState
      {
        PINProvisioning pin_provisioning;
        KeyInitializationRequestDecoder keyopreq_decoder;
        X509Certificate keyopreq_server_certificate;
        PlatformNegotiationRequestDecoder platform_decoder;        PlatformNegotiationResponseEncoder platform_encoder;      }

    static ProvisioningState getProvisioningState (HttpSession session) throws IOException
      {
        return (ProvisioningState)session.getAttribute (PROV_STATE);
      }

    void addLogotypeAndFooter (StringBuffer s, HttpSession session, PlatformNegotiationRequestDecoder platform_decoder) throws IOException
      {
        ImageData logotype = platform_decoder.getIssuerLogotype ();
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

  }
