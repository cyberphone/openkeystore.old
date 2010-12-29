
package org.webpki.sks.ws.client;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

import org.webpki.sks.ws.common.AbortProvisioningSession;
import org.webpki.sks.ws.common.AbortProvisioningSessionResponse;
import org.webpki.sks.ws.common.AddExtension;
import org.webpki.sks.ws.common.AddExtensionResponse;
import org.webpki.sks.ws.common.AsymmetricKeyDecrypt;
import org.webpki.sks.ws.common.AsymmetricKeyDecryptResponse;
import org.webpki.sks.ws.common.ChangePIN;
import org.webpki.sks.ws.common.ChangePINResponse;
import org.webpki.sks.ws.common.CloseProvisioningSession;
import org.webpki.sks.ws.common.CloseProvisioningSessionResponse;
import org.webpki.sks.ws.common.GetKeyHandle;
import org.webpki.sks.ws.common.GetKeyHandleResponse;
import org.webpki.sks.ws.common.GetKeyProtectionInfo;
import org.webpki.sks.ws.common.GetKeyProtectionInfoResponse;
import org.webpki.sks.ws.common.GetVersion;
import org.webpki.sks.ws.common.GetVersionResponse;
import org.webpki.sks.ws.common.SetCertificatePath;
import org.webpki.sks.ws.common.SetCertificatePathResponse;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.webpki.sks.ws.common package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _AddExtensionResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "addExtensionResponse");
    private final static QName _GetVersion_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "getVersion");
    private final static QName _CloseProvisioningSession_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "closeProvisioningSession");
    private final static QName _ChangePINResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "changePINResponse");
    private final static QName _GetKeyHandleResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "getKeyHandleResponse");
    private final static QName _AsymmetricKeyDecrypt_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "asymmetricKeyDecrypt");
    private final static QName _CloseProvisioningSessionResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "closeProvisioningSessionResponse");
    private final static QName _GetKeyHandle_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "getKeyHandle");
    private final static QName _AbortProvisioningSessionResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "abortProvisioningSessionResponse");
    private final static QName _AddExtension_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "addExtension");
    private final static QName _AsymmetricKeyDecryptResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "asymmetricKeyDecryptResponse");
    private final static QName _GetVersionResponse_QNAME = new QName("http://xmlns.webpki.org/sks/v0.61", "getVersionResponse");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.webpki.sks.ws.common
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link AsymmetricKeyDecryptResponse }
     * 
     */
    public AsymmetricKeyDecryptResponse createAsymmetricKeyDecryptResponse() {
        return new AsymmetricKeyDecryptResponse();
    }

    /**
     * Create an instance of {@link AbortProvisioningSessionResponse }
     * 
     */
    public AbortProvisioningSessionResponse createAbortProvisioningSessionResponse() {
        return new AbortProvisioningSessionResponse();
    }

    /**
     * Create an instance of {@link GetKeyProtectionInfo }
     * 
     */
    public GetKeyProtectionInfo createGetKeyProtectionInfo() {
        return new GetKeyProtectionInfo();
    }

    /**
     * Create an instance of {@link GetVersionResponse }
     * 
     */
    public GetVersionResponse createGetVersionResponse() {
        return new GetVersionResponse();
    }

    /**
     * Create an instance of {@link SKSExceptionBean }
     * 
     */
    public SKSExceptionBean createSKSException() {
        return new SKSExceptionBean();
    }

    /**
     * Create an instance of {@link SetCertificatePathResponse }
     * 
     */
    public SetCertificatePathResponse createSetCertificatePathResponse() {
        return new SetCertificatePathResponse();
    }

    /**
     * Create an instance of {@link GetKeyProtectionInfoResponse }
     * 
     */
    public GetKeyProtectionInfoResponse createGetKeyProtectionInfoResponse() {
        return new GetKeyProtectionInfoResponse();
    }

    /**
     * Create an instance of {@link AsymmetricKeyDecrypt }
     * 
     */
    public AsymmetricKeyDecrypt createAsymmetricKeyDecrypt() {
        return new AsymmetricKeyDecrypt();
    }

    /**
     * Create an instance of {@link AbortProvisioningSession }
     * 
     */
    public AbortProvisioningSession createAbortProvisioningSession() {
        return new AbortProvisioningSession();
    }

    /**
     * Create an instance of {@link GetKeyHandle }
     * 
     */
    public GetKeyHandle createGetKeyHandle() {
        return new GetKeyHandle();
    }

    /**
     * Create an instance of {@link AddExtension }
     * 
     */
    public AddExtension createAddExtension() {
        return new AddExtension();
    }

    /**
     * Create an instance of {@link AddExtensionResponse }
     * 
     */
    public AddExtensionResponse createAddExtensionResponse() {
        return new AddExtensionResponse();
    }

    /**
     * Create an instance of {@link SetCertificatePath }
     * 
     */
    public SetCertificatePath createSetCertificatePath() {
        return new SetCertificatePath();
    }

    /**
     * Create an instance of {@link GetKeyHandleResponse }
     * 
     */
    public GetKeyHandleResponse createGetKeyHandleResponse() {
        return new GetKeyHandleResponse();
    }

    /**
     * Create an instance of {@link CloseProvisioningSession }
     * 
     */
    public CloseProvisioningSession createCloseProvisioningSession() {
        return new CloseProvisioningSession();
    }

    /**
     * Create an instance of {@link ChangePIN }
     * 
     */
    public ChangePIN createChangePIN() {
        return new ChangePIN();
    }

    /**
     * Create an instance of {@link ChangePINResponse }
     * 
     */
    public ChangePINResponse createChangePINResponse() {
        return new ChangePINResponse();
    }

    /**
     * Create an instance of {@link CloseProvisioningSessionResponse }
     * 
     */
    public CloseProvisioningSessionResponse createCloseProvisioningSessionResponse() {
        return new CloseProvisioningSessionResponse();
    }

    /**
     * Create an instance of {@link GetVersion }
     * 
     */
    public GetVersion createGetVersion() {
        return new GetVersion();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AddExtensionResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "addExtensionResponse")
    public JAXBElement<AddExtensionResponse> createAddExtensionResponse(AddExtensionResponse value) {
        return new JAXBElement<AddExtensionResponse>(_AddExtensionResponse_QNAME, AddExtensionResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetVersion }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "getVersion")
    public JAXBElement<GetVersion> createGetVersion(GetVersion value) {
        return new JAXBElement<GetVersion>(_GetVersion_QNAME, GetVersion.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CloseProvisioningSession }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "closeProvisioningSession")
    public JAXBElement<CloseProvisioningSession> createCloseProvisioningSession(CloseProvisioningSession value) {
        return new JAXBElement<CloseProvisioningSession>(_CloseProvisioningSession_QNAME, CloseProvisioningSession.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ChangePINResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "changePINResponse")
    public JAXBElement<ChangePINResponse> createChangePINResponse(ChangePINResponse value) {
        return new JAXBElement<ChangePINResponse>(_ChangePINResponse_QNAME, ChangePINResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetKeyHandleResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "getKeyHandleResponse")
    public JAXBElement<GetKeyHandleResponse> createGetKeyHandleResponse(GetKeyHandleResponse value) {
        return new JAXBElement<GetKeyHandleResponse>(_GetKeyHandleResponse_QNAME, GetKeyHandleResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AsymmetricKeyDecrypt }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "asymmetricKeyDecrypt")
    public JAXBElement<AsymmetricKeyDecrypt> createAsymmetricKeyDecrypt(AsymmetricKeyDecrypt value) {
        return new JAXBElement<AsymmetricKeyDecrypt>(_AsymmetricKeyDecrypt_QNAME, AsymmetricKeyDecrypt.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CloseProvisioningSessionResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "closeProvisioningSessionResponse")
    public JAXBElement<CloseProvisioningSessionResponse> createCloseProvisioningSessionResponse(CloseProvisioningSessionResponse value) {
        return new JAXBElement<CloseProvisioningSessionResponse>(_CloseProvisioningSessionResponse_QNAME, CloseProvisioningSessionResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetKeyHandle }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "getKeyHandle")
    public JAXBElement<GetKeyHandle> createGetKeyHandle(GetKeyHandle value) {
        return new JAXBElement<GetKeyHandle>(_GetKeyHandle_QNAME, GetKeyHandle.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AbortProvisioningSessionResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "abortProvisioningSessionResponse")
    public JAXBElement<AbortProvisioningSessionResponse> createAbortProvisioningSessionResponse(AbortProvisioningSessionResponse value) {
        return new JAXBElement<AbortProvisioningSessionResponse>(_AbortProvisioningSessionResponse_QNAME, AbortProvisioningSessionResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AddExtension }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "addExtension")
    public JAXBElement<AddExtension> createAddExtension(AddExtension value) {
        return new JAXBElement<AddExtension>(_AddExtension_QNAME, AddExtension.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AsymmetricKeyDecryptResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "asymmetricKeyDecryptResponse")
    public JAXBElement<AsymmetricKeyDecryptResponse> createAsymmetricKeyDecryptResponse(AsymmetricKeyDecryptResponse value) {
        return new JAXBElement<AsymmetricKeyDecryptResponse>(_AsymmetricKeyDecryptResponse_QNAME, AsymmetricKeyDecryptResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetVersionResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://xmlns.webpki.org/sks/v0.61", name = "getVersionResponse")
    public JAXBElement<GetVersionResponse> createGetVersionResponse(GetVersionResponse value) {
        return new JAXBElement<GetVersionResponse>(_GetVersionResponse_QNAME, GetVersionResponse.class, null, value);
    }

}
