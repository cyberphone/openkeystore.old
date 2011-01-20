package org.webpki.sks.ws.server;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Holder;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

import org.webpki.sks.SKSException;

import com.sun.xml.ws.developer.SchemaValidation;

@SchemaValidation
@WebService(targetNamespace="http://xmlns.webpki.org/sks/v0.61",
            serviceName="SKSWS",
            portName="SKSWSPort",
            wsdlLocation="META-INF/SKSWS.wsdl")
public class SKSWSImplementation
  {

    @WebMethod
    @RequestWrapper(localName = "abortProvisioningSession", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.AbortProvisioningSession")
    @ResponseWrapper(localName = "abortProvisioningSessionResponse", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.AbortProvisioningSessionResponse")
    public void abortProvisioningSession(
        @WebParam(name = "keyHandle", targetNamespace = "")
        int keyHandle)
        throws SKSException
    {
      if (keyHandle == 5)
        {
          throw new SKSException ("bad",4);
        }
      // TODO Auto-generated method stub
      
    }


    @WebMethod(operationName="getKeyProtectionInfo")
 //   @RequestWrapper(localName = "getKeyProtectionInfo", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.getKeyProtectionInfo")
 //   @ResponseWrapper(localName = "getKeyProtectionInfoResponse", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.getKeyProtectionInfoResponse")
    public void getKeyProtectionInfo(
        @WebParam(name = "keyHandle", targetNamespace = "")
        int keyHandle,
        @WebParam(name = "ProtectionStatus", targetNamespace = "", mode = WebParam.Mode.OUT)
        Holder<String> protectionStatus,
        @WebParam(name = "blah", targetNamespace = "", mode = WebParam.Mode.OUT)
        Holder<Byte> blah)
      throws SKSException
    {
      protectionStatus.value = "yes";
      blah.value = (byte)(keyHandle + 2);
      // TODO Auto-generated method stub
      
    }
    @WebMethod
    @RequestWrapper(localName = "setCertificatePath", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.SetCertificatePath")
    @ResponseWrapper(localName = "setCertificatePathResponse", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.SetCertificatePathResponse")
    public void setCertificatePath(
        @WebParam(name = "KeyHandle", targetNamespace = "")
        int key_handle,
        @WebParam(name = "X509Certificate", targetNamespace = "")
        List<byte[]> x509_certificate,
        @WebParam(name = "MAC", targetNamespace = "")
        byte[] mac)
        throws SKSException
        {
          System.out.println ("Certs=" + x509_certificate.size () + " mac=" + mac.length);
        }

  @WebMethod
  @WebResult(targetNamespace = "")
  @RequestWrapper(localName = "getVersion", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.GetVersion")
  @ResponseWrapper(localName = "getVersionResponse", targetNamespace = "http://xmlns.webpki.org/sks/v0.61", className = "org.webpki.sks.ws.common.GetVersionResponse")
  public String getVersion()
    {
      // TODO Auto-generated method stub
      return "0.00001";
    }

    public static void main (String[] args) throws Exception
      {
        if (args.length != 1)
          {
            System.out.println ("Missing URL");
          }
        URL wsdlResource = SKSWSImplementation.class.getResource ("/META-INF/SKSWS.wsdl");

        List<Source> metadata = new ArrayList<Source> ();

        Source source = new StreamSource (wsdlResource.openStream ());
        source.setSystemId (wsdlResource.toExternalForm ());
        metadata.add (source);

        Map<String,Object> properties = new HashMap<String,Object> ();

        properties.put (Endpoint.WSDL_PORT, new QName ("http://xmlns.webpki.org/sks/v0.61", "SKSWSPort"));
        properties.put (Endpoint.WSDL_SERVICE, new QName ("http://xmlns.webpki.org/sks/v0.61", "SKSWS"));

        Endpoint endpoint = Endpoint.create (new SKSWSImplementation ());
//        endpoint.setMetadata (metadata);
        endpoint.setProperties (properties);
        endpoint.publish (args[0]);
      }

  }
