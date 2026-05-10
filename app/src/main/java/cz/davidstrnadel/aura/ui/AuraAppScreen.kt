package cz.davidstrnadel.aura.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.DefensivePostureSummary
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding
import cz.davidstrnadel.aura.core.EvidenceGraph
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.RecommendedAction
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuraAppScreen(viewModel: AuraViewModel = viewModel()) {
    val state by viewModel.state.collectAsState()
    var selectedPackage by remember { mutableStateOf<String?>(null) }
    val selectedAssessment = remember(state.assessments, selectedPackage) {
        state.assessments.firstOrNull { it.snapshot.packageName == selectedPackage }
            ?: state.assessments.firstOrNull()
    }

    LaunchedEffect(state.scanId) {
        selectedPackage = null
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("AURA") },
                actions = {
                    Button(onClick = viewModel::rescan) {
                        Icon(Icons.Default.Refresh, contentDescription = null)
                        Text("Scan")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            when {
                state.loading -> LoadingState()
                state.error != null -> Text("Scan failed: ${state.error}", color = MaterialTheme.colorScheme.error)
                else -> {
                    SummaryRow(state)
                    ScanHistoryRow(state)
                    Spacer(Modifier.height(12.dp))
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        item {
                            selectedAssessment?.let { assessment ->
                                AppDetailPanel(
                                    assessment = assessment,
                                    findings = state.defensiveSurfaceFindings.filter {
                                        it.packageName == assessment.snapshot.packageName
                                    },
                                    posture = state.defensivePostures.firstOrNull {
                                        it.packageName == assessment.snapshot.packageName
                                    }
                                )
                            }
                        }
                        items(state.assessments.take(40), key = { it.snapshot.packageName }) { assessment ->
                            AssessmentRow(
                                assessment = assessment,
                                selected = assessment.snapshot.packageName == selectedAssessment?.snapshot?.packageName,
                                onClick = { selectedPackage = assessment.snapshot.packageName }
                            )
                        }
                        item {
                            ExportPanel(state)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LoadingState() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator()
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SummaryRow(state: AuraUiState) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        CountChip("RED", state.redCount, DecisionColor.RED)
        CountChip("YELLOW", state.yellowCount, DecisionColor.YELLOW)
        CountChip("BLUE", state.blueCount, DecisionColor.BLUE)
        CountChip("GRAY", state.grayCount, DecisionColor.GRAY)
        CountChip("GREEN", state.greenCount, DecisionColor.GREEN)
        AssistChip(onClick = {}, label = { Text("DEF ${state.defensiveFindingCount}") })
        AssistChip(onClick = {}, label = { Text("PKG ${state.assessments.size}") })
    }
}

@Composable
private fun CountChip(label: String, count: Int, color: DecisionColor) {
    AssistChip(
        onClick = {},
        label = { Text("$label $count") },
        leadingIcon = {
            Icon(
                Icons.Default.Science,
                contentDescription = null,
                tint = decisionTint(color)
            )
        }
    )
}

@Composable
private fun ScanHistoryRow(state: AuraUiState) {
    val history = state.scanHistory ?: return
    Spacer(Modifier.height(8.dp))
    Text(
        text = "history scans=${history.retainedScanCount} packages=${history.retainedPackageCount} changed=${history.packagesChangedSincePreviousScan.size} new=${history.packagesNewInThisScan.size} removed=${history.packagesRemovedSincePreviousScan.size}",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace
    )
}

@Composable
private fun AssessmentRow(
    assessment: AuraAssessment,
    selected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        tonalElevation = if (selected) 3.dp else 1.dp,
        shape = MaterialTheme.shapes.small,
        color = if (selected) {
            MaterialTheme.colorScheme.secondaryContainer
        } else {
            MaterialTheme.colorScheme.surface
        },
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Science, contentDescription = null, tint = decisionTint(assessment.decision.color))
                Text(
                    text = assessment.decision.color.name,
                    modifier = Modifier.padding(start = 8.dp),
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " ${assessment.decision.title}",
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Text(
                text = assessment.snapshot.appLabel.ifBlank { assessment.snapshot.packageName },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = assessment.snapshot.packageName,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "role=${assessment.role.predicted} provenance=${assessment.provenance.provenanceClass} action=${assessment.decision.actionabilityClass}",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun AppDetailPanel(
    assessment: AuraAssessment,
    findings: List<DefensiveSurfaceFinding>,
    posture: DefensivePostureSummary?
) {
    SectionSurface {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Info, contentDescription = null)
            Text(
                text = "Selected app",
                modifier = Modifier.padding(start = 8.dp),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
        Spacer(Modifier.height(8.dp))
        KeyValue("package", assessment.snapshot.packageName)
        KeyValue("decision", "${assessment.decision.color} / ${assessment.decision.title}")
        KeyValue("userAlert", assessment.decision.userAlert.toString())
        KeyValue("expertFinding", assessment.decision.expertFinding.toString())
        KeyValue("role", "${assessment.role.predicted} (${scoreText(assessment.role.confidence)})")
        KeyValue("provenance", "${assessment.provenance.provenanceClass} (${scoreText(assessment.provenance.confidence)})")
        KeyValue("actionability", assessment.decision.actionabilityClass.name)
        KeyValue("defensive posture", posture?.postureClass?.name ?: "NO_OBSERVED_WEAKNESS")
        KeyValue("installer", assessment.snapshot.installerPackageName ?: "none")
        KeyValue("source", assessment.snapshot.rawFeatures["sourcePartition"] ?: assessment.snapshot.sourceDir)
        Spacer(Modifier.height(12.dp))
        UserRiskStoryPanel(assessment)
        Spacer(Modifier.height(12.dp))
        RiskVectorBars(assessment)
        Spacer(Modifier.height(12.dp))
        Text(
            text = assessment.decision.explanation,
            style = MaterialTheme.typography.bodyMedium
        )
        RecommendedActionsList(assessment.decision.recommendedActions)
        DecisionTraceSummary(assessment)
        EvidenceGraphSummary(assessment.evidenceGraph)
        EvidenceList(assessment.evidence)
        DefensivePosturePanel(posture, findings)
    }
}

@Composable
private fun UserRiskStoryPanel(assessment: AuraAssessment) {
    val story = assessment.userRiskStory
    Text(story.headline, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
    Text(story.primaryReason, style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(6.dp))
    Text(
        text = "next=${story.recommendedNextStep}",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace
    )
    story.whatWasObserved.take(4).forEach { observed ->
        Text(
            text = "+ $observed",
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun RiskVectorBars(assessment: AuraAssessment) {
    Text("Risk vector", style = MaterialTheme.typography.titleSmall)
    ScoreBar("harm", assessment.riskVector.harm)
    ScoreBar("legitimacy", assessment.riskVector.legitimacy)
    ScoreBar("abuse", assessment.riskVector.abuseEvidence)
    ScoreBar("provenance", assessment.riskVector.provenanceConfidence)
    ScoreBar("actionability", assessment.riskVector.actionability)
    ScoreBar("uncertainty", assessment.riskVector.uncertainty)
}

@Composable
private fun ScoreBar(label: String, value: Double) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(0.34f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1
        )
        LinearProgressIndicator(
            progress = { value.toFloat().coerceIn(0f, 1f) },
            modifier = Modifier
                .weight(0.48f)
                .padding(horizontal = 8.dp)
        )
        Text(
            text = scoreText(value),
            modifier = Modifier.weight(0.18f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1
        )
    }
}

@Composable
private fun EvidenceList(evidence: List<EvidenceItem>) {
    Spacer(Modifier.height(12.dp))
    Text("Evidence", style = MaterialTheme.typography.titleSmall)
    evidence.take(8).forEach { item ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${item.source} ${scoreText(item.confidence)} ${item.observabilityState}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = item.humanExplanation,
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            text = item.normalizedValue,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun RecommendedActionsList(actions: List<RecommendedAction>) {
    if (actions.isEmpty()) return
    Spacer(Modifier.height(12.dp))
    Text("Recommended actions", style = MaterialTheme.typography.titleSmall)
    actions.take(6).forEach { action ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${action.actionId} ${action.scope} ${action.actionabilityClass}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = action.title,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold
        )
        Text(
            text = action.description,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun EvidenceGraphSummary(graph: EvidenceGraph) {
    if (graph.nodes.isEmpty()) return
    Spacer(Modifier.height(12.dp))
    Text("Evidence graph", style = MaterialTheme.typography.titleSmall)
    Text(
        text = "nodes=${graph.nodes.size} edges=${graph.edges.size}",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace
    )
    graph.edges.take(8).forEach { edge ->
        Spacer(Modifier.height(4.dp))
        Text(
            text = "${edge.from} ${edge.relation} ${edge.to}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun DecisionTraceSummary(assessment: AuraAssessment) {
    val trace = assessment.decisionTrace
    Spacer(Modifier.height(12.dp))
    Text("Decision trace", style = MaterialTheme.typography.titleSmall)
    Text(
        text = "policy=${trace.policyVersion} selected=${trace.selectedDecision} matched=${trace.evaluatedRules.count { it.matched }} invariants=${trace.invariantChecks.count { it.passed }}/${trace.invariantChecks.size}",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace
    )
    trace.evaluatedRules.filter { it.matched }.take(3).forEach { rule ->
        Spacer(Modifier.height(4.dp))
        Text(
            text = "${rule.ruleId}: ${rule.explanation}",
            style = MaterialTheme.typography.bodySmall
        )
    }
    trace.counterfactuals.firstOrNull()?.let { counterfactual ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "counterfactual ${counterfactual.targetDecision}: ${counterfactual.requiredChanges.joinToString("; ")}",
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun DefensivePosturePanel(
    posture: DefensivePostureSummary?,
    findings: List<DefensiveSurfaceFinding>
) {
    Spacer(Modifier.height(12.dp))
    Text("Defensive posture", style = MaterialTheme.typography.titleSmall)
    Text(
        text = posture?.userFacingSummary ?: "No defensive-surface weakness was observed by the current metadata-only audit.",
        style = MaterialTheme.typography.bodySmall
    )
    if (findings.isEmpty()) return
    findings.take(8).forEach { finding ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${finding.findingType} ${finding.severity} ${scoreText(finding.confidence)}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = finding.humanExplanation,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun ExportPanel(state: AuraUiState) {
    Spacer(Modifier.height(12.dp))
    if (state.exportPath.isNotBlank()) {
        Text(
            text = "export=${state.exportPath}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.height(8.dp))
    }
    SectionSurface {
        Text("JSON preview", style = MaterialTheme.typography.titleSmall)
        Text(
            text = state.exportPreview,
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun SectionSurface(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp), content = content)
    }
}

@Composable
private fun KeyValue(key: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = key,
            modifier = Modifier.weight(0.34f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.66f),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

private fun scoreText(value: Double): String = String.format(Locale.US, "%.2f", value)

@Composable
private fun decisionTint(color: DecisionColor): Color = when (color) {
    DecisionColor.RED -> MaterialTheme.colorScheme.error
    DecisionColor.YELLOW -> MaterialTheme.colorScheme.tertiary
    DecisionColor.BLUE -> MaterialTheme.colorScheme.primary
    DecisionColor.GRAY -> MaterialTheme.colorScheme.outline
    DecisionColor.GREEN -> MaterialTheme.colorScheme.secondary
}
