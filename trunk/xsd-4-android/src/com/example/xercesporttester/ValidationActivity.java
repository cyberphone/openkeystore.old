package com.example.xercesporttester;

import android.os.Bundle;
import android.app.Activity;
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
