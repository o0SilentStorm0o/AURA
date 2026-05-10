package com.example.leakybank;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class ExportedSyncService extends Service {
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
