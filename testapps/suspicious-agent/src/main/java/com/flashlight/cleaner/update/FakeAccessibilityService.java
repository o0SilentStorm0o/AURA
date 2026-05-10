package com.flashlight.cleaner.update;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;

public class FakeAccessibilityService extends AccessibilityService {
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // Intentionally empty. This lab APK declares capability without harmful behavior.
    }

    @Override
    public void onInterrupt() {
        // Intentionally empty.
    }
}
