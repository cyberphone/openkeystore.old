
package org.webpki.sks.ws.common;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for asymmetricKeyDecrypt complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="asymmetricKeyDecrypt">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="arg0" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="arg1" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="arg2" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="arg3" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element name="arg4" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "asymmetricKeyDecrypt", propOrder = {
    "arg0",
    "arg1",
    "arg2",
    "arg3",
    "arg4"
})
public class AsymmetricKeyDecrypt {

    protected int arg0;
    @XmlElement(required = true)
    protected String arg1;
    @XmlElement(required = true)
    protected byte[] arg2;
    @XmlElement(required = true)
    protected byte[] arg3;
    @XmlElement(required = true)
    protected byte[] arg4;

    /**
     * Gets the value of the arg0 property.
     * 
     */
    public int getArg0() {
        return arg0;
    }

    /**
     * Sets the value of the arg0 property.
     * 
     */
    public void setArg0(int value) {
        this.arg0 = value;
    }

    /**
     * Gets the value of the arg1 property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getArg1() {
        return arg1;
    }

    /**
     * Sets the value of the arg1 property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setArg1(String value) {
        this.arg1 = value;
    }

    /**
     * Gets the value of the arg2 property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getArg2() {
        return arg2;
    }

    /**
     * Sets the value of the arg2 property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setArg2(byte[] value) {
        this.arg2 = ((byte[]) value);
    }

    /**
     * Gets the value of the arg3 property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getArg3() {
        return arg3;
    }

    /**
     * Sets the value of the arg3 property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setArg3(byte[] value) {
        this.arg3 = ((byte[]) value);
    }

    /**
     * Gets the value of the arg4 property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getArg4() {
        return arg4;
    }

    /**
     * Sets the value of the arg4 property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setArg4(byte[] value) {
        this.arg4 = ((byte[]) value);
    }

}
