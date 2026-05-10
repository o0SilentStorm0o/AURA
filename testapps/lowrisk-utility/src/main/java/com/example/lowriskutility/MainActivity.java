package com.example.lowriskutility;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setText("Low exposure unknown utility fixture");
        view.setTextSize(20f);
        setContentView(view);
    }
}
