package cz.davidstrnadel.aura

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import cz.davidstrnadel.aura.ui.AuraAppScreen
import cz.davidstrnadel.aura.ui.theme.AuraTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        installSplashScreen()
        super.onCreate(savedInstanceState)
        setContent {
            AuraTheme {
                AuraAppScreen()
            }
        }
    }
}
