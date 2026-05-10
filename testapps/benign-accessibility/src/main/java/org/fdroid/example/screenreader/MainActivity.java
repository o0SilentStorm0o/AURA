package org.fdroid.example.screenreader;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setText("Harmless accessibility-tool fixture");
        view.setTextSize(20f);
        setContentView(view);
    }
}
