package com.flashlight.cleaner.update;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setText("Harmless AURA suspicious scenario app");
        view.setTextSize(20f);
        setContentView(view);
    }
}
