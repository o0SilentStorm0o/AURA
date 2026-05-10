package org.fdroid.example.screenreader;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;

public class ScreenReaderAccessibilityService extends AccessibilityService {
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // Intentionally empty. This fixture exists only for role-normalization tests.
    }

    @Override
    public void onInterrupt() {
        // Intentionally empty.
    }
}
