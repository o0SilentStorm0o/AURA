package cz.davidstrnadel.aura.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF145C58),
    secondary = Color(0xFF7A3E12),
    tertiary = Color(0xFF445E91),
    surface = Color(0xFFFBFCF8),
    surfaceVariant = Color(0xFFE4E9E3)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF7ED7CF),
    secondary = Color(0xFFFFB477),
    tertiary = Color(0xFFB9C7FF),
    surface = Color(0xFF101412),
    surfaceVariant = Color(0xFF3F4946)
)

@Composable
fun AuraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = LightColors,
        content = content
    )
}
