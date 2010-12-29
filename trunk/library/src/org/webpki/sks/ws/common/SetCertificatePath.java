
package org.webpki.sks.ws.common;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="keyHandle" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="x509Certificate" type="{http://www.w3.org/2001/XMLSchema}base64Binary" maxOccurs="unbounded"/>
 *         &lt;element name="mac" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "keyHandle",
    "x509Certificate",
    "mac"
})
@XmlRootElement(name = "setCertificatePath")
public class SetCertificatePath {

    protected int keyHandle;
    @XmlElement(required = true)
    protected List<byte[]> x509Certificate;
    @XmlElement(required = true)
    protected byte[] mac;

    /**
     * Gets the value of the keyHandle property.
     * 
     */
    public int getKeyHandle() {
        return keyHandle;
    }

    /**
     * Sets the value of the keyHandle property.
     * 
     */
    public void setKeyHandle(int value) {
        this.keyHandle = value;
    }

    /**
     * Gets the value of the x509Certificate property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the x509Certificate property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getX509Certificate().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * byte[]
     * 
     */
    public List<byte[]> getX509Certificate() {
        if (x509Certificate == null) {
            x509Certificate = new ArrayList<byte[]>();
        }
        return this.x509Certificate;
    }

    /**
     * Gets the value of the mac property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getMac() {
        return mac;
    }

    /**
     * Sets the value of the mac property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setMac(byte[] value) {
        this.mac = ((byte[]) value);
    }

}
