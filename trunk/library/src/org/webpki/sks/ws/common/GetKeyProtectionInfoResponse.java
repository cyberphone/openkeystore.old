
package org.webpki.sks.ws.common;

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
 *         &lt;element name="protectionStatus" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="blah" type="{http://www.w3.org/2001/XMLSchema}byte"/>
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
    "protectionStatus",
    "blah"
})
@XmlRootElement(name = "getKeyProtectionInfoResponse")
public class GetKeyProtectionInfoResponse {

    @XmlElement(required = true)
    protected String protectionStatus;
    protected byte blah;

    /**
     * Gets the value of the protectionStatus property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProtectionStatus() {
        return protectionStatus;
    }

    /**
     * Sets the value of the protectionStatus property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProtectionStatus(String value) {
        this.protectionStatus = value;
    }

    /**
     * Gets the value of the blah property.
     * 
     */
    public byte getBlah() {
        return blah;
    }

    /**
     * Sets the value of the blah property.
     * 
     */
    public void setBlah(byte value) {
        this.blah = value;
    }

}
