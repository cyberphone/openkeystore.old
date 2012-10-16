package com.example.xercesporttester;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class ValidationActivity extends Activity {
	
	TextView validation_result;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_validation);
        
        validation_result = (TextView)findViewById (R.id.validationResult);
        
        Intent intent = getIntent();
        String xml_message = intent.getStringExtra(MainActivity.XML_MESSAGE);
        try
        {
	        DocumentBuilder parser = MainActivity.dbf.newDocumentBuilder ();
	        Document document = parser.parse (new ByteArrayInputStream (xml_message.getBytes ("UTF-8")));
            Validator validator = MainActivity.schema.newValidator ();
            validator.validate (new DOMSource (document));
        	validation_result.setTextColor(Color.GREEN);
	    	validation_result.setText("XML validated OK");
        }
        catch (Exception e)
        {
        	ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        	PrintWriter printer_writer = new PrintWriter (baos);
        	e.printStackTrace(printer_writer);
        	printer_writer.flush();
        	validation_result.setTextColor(Color.RED);
        	try {
				validation_result.setText(baos.toString("UTF-8"));
			} catch (UnsupportedEncodingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
        }

        Button return2main = (Button)findViewById (R.id.return2main);
        return2main.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                validation_result.setText("Yeah!");
                finish ();
            }
        });

    }

  
}
