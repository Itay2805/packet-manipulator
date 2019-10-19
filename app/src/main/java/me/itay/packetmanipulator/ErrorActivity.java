package me.itay.packetmanipulator;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

public class ErrorActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_error);

        // get the controls
        TextView txtError = findViewById(R.id.txtError);

        // get the error and set it
        String errorString = getIntent().getStringExtra("EXTRA_ERROR_STRING");
        txtError.setText(errorString);
    }
}
