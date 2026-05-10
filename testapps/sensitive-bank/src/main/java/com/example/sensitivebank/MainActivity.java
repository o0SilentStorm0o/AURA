package com.example.sensitivebank;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );
        TextView view = new TextView(this);
        view.setText("Fixture banking app with FLAG_SECURE");
        view.setTextSize(20f);
        setContentView(view);
    }
}
