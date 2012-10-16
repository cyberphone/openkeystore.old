package com.example.xercesporttester;

import javax.xml.parsers.DocumentBuilderFactory;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

import org.webpki.android.org.apache.env.WhichXerces;

public class MainActivity extends Activity {

    static String xsd1 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig11\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:element name=\"ECKeyValue\" type=\"xs:base64Binary\"/>" +
        
        "</xs:schema>";

    static String xsd2 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig\"" +
        "           xmlns:ds=\"http://example.com/xmldsig\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:import namespace=\"http://example.com/xmldsig11\"/>" +

        "   <xs:element name=\"KeyInfo\">" +
        "      <xs:complexType>" +
        "         <xs:sequence>" +
        "            <xs:element ref=\"ds11:ECKeyValue\"/>" +
        "         </xs:sequence>" +
        "      </xs:complexType>" +
        "   </xs:element>" +

        "</xs:schema>";
      
    static String xsd3 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig3\"" +
        "           xmlns:ds=\"http://example.com/xmldsig3\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:import namespace=\"http://example.com/xmldsig11\"/>" +

        "   <xs:element name=\"KeyInfo\">" +
        "      <xs:complexType>" +
        "         <xs:sequence>" +
        "            <xs:element ref=\"ds11:ECKeyValue\"/>" +
        "         </xs:sequence>" +
        "      </xs:complexType>" +
        "   </xs:element>" +

        "</xs:schema>";

    static String xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
        "<key:KeyInfo xmlns:key=\"http://example.com/xmldsig\"" +
        " xmlns:ds11=\"http://example.com/xmldsig11\">\n" +
        "  <ds11:ECKeyValue>\nAmA0R1CUdde3nakEJAFEqa29xtYQRaRXc7zB+iTOsV4=\n  </ds11:ECKeyValue>\n" +
        "</key:KeyInfo>";
    
    static DocumentBuilderFactory dbf;
    
    EditText xml_control;
    
    void restoreXML ()
    {
    	xml_control.setText(xml);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        xml_control = (EditText) findViewById(R.id.editXML);

        Button restoreXML = (Button)findViewById(R.id.buttonRestoreXML);
        restoreXML.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                restoreXML ();
            }
        });

        Button validateXML = (Button)findViewById (R.id.buttonValidateXML);
        validateXML.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent i = new Intent(MainActivity.this, ValidationActivity.class);
                startActivity(i);
            }
        });

        restoreXML ();
        new WhichXerces ();
    	if (dbf != null) try
    	{
    		dbf = DocumentBuilderFactory.newInstance ("org.webpki.android.org.apache.xerces.jaxp.DocumentBuilderFactoryImpl",
    				                                  MainActivity.class.getClassLoader ());
    	}
    	catch (Exception e)
    	{
    		throw new RuntimeException (e);
    	}
    }

}
