package cz.davidstrnadel.aura.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import cz.davidstrnadel.aura.collector.AppSnapshotCollector
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.export.AuraJsonExporter
import cz.davidstrnadel.aura.export.AuraScanExport
import cz.davidstrnadel.aura.reasoning.AuraAssessmentEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID

data class AuraUiState(
    val loading: Boolean = true,
    val scanId: String = "",
    val assessments: List<AuraAssessment> = emptyList(),
    val exportPreview: String = "",
    val exportPath: String = "",
    val error: String? = null
) {
    val redCount: Int = assessments.count { it.decision.color == DecisionColor.RED }
    val blueCount: Int = assessments.count { it.decision.color == DecisionColor.BLUE }
    val grayCount: Int = assessments.count { it.decision.color == DecisionColor.GRAY }
    val yellowCount: Int = assessments.count { it.decision.color == DecisionColor.YELLOW }
    val greenCount: Int = assessments.count { it.decision.color == DecisionColor.GREEN }
}

class AuraViewModel(application: Application) : AndroidViewModel(application) {
    private val collector = AppSnapshotCollector(application)
    private val assessmentEngine = AuraAssessmentEngine()
    private val exporter = AuraJsonExporter()
    private val _state = MutableStateFlow(AuraUiState())

    val state: StateFlow<AuraUiState> = _state.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch(Dispatchers.Default) {
            val scanId = UUID.randomUUID().toString()
            _state.value = AuraUiState(loading = true, scanId = scanId)
            runCatching {
                val assessments = collector.collect(scanId)
                    .map { assessmentEngine.assess(it) }
                    .sortedWith(compareBy<AuraAssessment> { decisionRank(it) }.thenBy { it.snapshot.packageName })
                val flavor = assessments.firstOrNull()?.snapshot?.flavor.orEmpty()
                val export = AuraScanExport(
                    schemaVersion = 1,
                    scanId = scanId,
                    generatedAt = System.currentTimeMillis(),
                    flavor = flavor,
                    assessments = assessments,
                    temporalEpisodes = emptyList()
                )
                val json = exporter.toJson(export)
                val exportFile = getApplication<Application>()
                    .filesDir
                    .resolve("exports")
                    .also { it.mkdirs() }
                    .resolve("aura-last-scan.json")
                exportFile.writeText(json)
                _state.value = AuraUiState(
                    loading = false,
                    scanId = scanId,
                    assessments = assessments,
                    exportPreview = json.take(1600),
                    exportPath = exportFile.absolutePath
                )
            }.onFailure { error ->
                _state.value = AuraUiState(
                    loading = false,
                    scanId = scanId,
                    error = error.message ?: error::class.java.simpleName
                )
            }
        }
    }

    private fun decisionRank(assessment: AuraAssessment): Int = when (assessment.decision.color) {
        DecisionColor.RED -> 0
        DecisionColor.YELLOW -> 1
        DecisionColor.BLUE -> 2
        DecisionColor.GRAY -> 3
        DecisionColor.GREEN -> 4
    }
}
