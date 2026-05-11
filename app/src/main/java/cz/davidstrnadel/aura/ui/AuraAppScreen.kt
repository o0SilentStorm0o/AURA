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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DecisionColor
import cz.davidstrnadel.aura.core.DefensivePostureClass
import cz.davidstrnadel.aura.core.DefensivePostureSummary
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding
import cz.davidstrnadel.aura.core.EvidenceGraph
import cz.davidstrnadel.aura.core.EvidenceItem
import cz.davidstrnadel.aura.core.ObservabilityState
import cz.davidstrnadel.aura.core.RecommendedAction
import cz.davidstrnadel.aura.core.TemporalEpisode
import java.util.Locale

private enum class AudienceMode(
    val label: String,
    val description: String,
    val icon: ImageVector
) {
    BASIC("Basic", "What matters and what to do", Icons.Default.Security),
    POWER("Power", "Risk vector and system signals", Icons.Default.Tune),
    RESEARCH("Research", "Trace, graph, limits, export", Icons.Default.Science)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuraAppScreen(viewModel: AuraViewModel = viewModel()) {
    val state by viewModel.state.collectAsState()
    var selectedPackage by remember { mutableStateOf<String?>(null) }
    var audienceMode by remember { mutableStateOf(AudienceMode.BASIC) }
    val selectedAssessment = remember(state.assessments, selectedPackage) {
        state.assessments.firstOrNull { it.snapshot.packageName == selectedPackage }
            ?: state.assessments.firstOrNull()
    }
    val visibleAssessments = remember(state, audienceMode) {
        visibleAssessmentsForMode(state, audienceMode)
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
        when {
            state.loading -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(16.dp)
                ) {
                    LoadingState()
                }
            }
            state.error != null -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(16.dp)
                ) {
                    Text("Scan failed: ${state.error}", color = MaterialTheme.colorScheme.error)
                }
            }
            else -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item {
                        ModeSelector(
                            selected = audienceMode,
                            onSelected = { audienceMode = it }
                        )
                    }
                    item {
                        ActionDashboard(state)
                    }
                    item {
                        selectedAssessment?.let { assessment ->
                            AppDetailPanel(
                                assessment = assessment,
                                findings = state.defensiveSurfaceFindings.filter {
                                    it.packageName == assessment.snapshot.packageName
                                },
                                posture = state.defensivePostures.firstOrNull {
                                    it.packageName == assessment.snapshot.packageName
                                },
                                episodes = state.temporalEpisodes.filter {
                                    it.packageName == assessment.snapshot.packageName
                                },
                                state = state,
                                mode = audienceMode
                            )
                        }
                    }
                    item {
                        AppListHeader(state, visibleAssessments, audienceMode)
                    }
                    items(visibleAssessments, key = { it.snapshot.packageName }) { assessment ->
                        AssessmentRow(
                            assessment = assessment,
                            posture = state.defensivePostures.firstOrNull {
                                it.packageName == assessment.snapshot.packageName
                            },
                            episodeCount = state.temporalEpisodes.count {
                                it.packageName == assessment.snapshot.packageName
                            },
                            selected = assessment.snapshot.packageName == selectedAssessment?.snapshot?.packageName,
                            onClick = { selectedPackage = assessment.snapshot.packageName }
                        )
                    }
                    if (audienceMode == AudienceMode.RESEARCH) {
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
private fun ModeSelector(
    selected: AudienceMode,
    onSelected: (AudienceMode) -> Unit
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        AudienceMode.entries.forEach { mode ->
            FilterChip(
                selected = selected == mode,
                onClick = { onSelected(mode) },
                label = { Text(mode.label) },
                leadingIcon = { Icon(mode.icon, contentDescription = null) }
            )
        }
    }
    Text(
        text = selected.description,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ActionDashboard(state: AuraUiState) {
    SectionSurface {
        Text("Device risk overview", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            DashboardMetric("Action required", state.redCount, "Primary user-alert queue", DecisionColor.RED, Icons.Default.Error)
            DashboardMetric("Review", state.yellowCount, "Worth checking, not panic", DecisionColor.YELLOW, Icons.Default.Visibility)
            DashboardMetric("Technical audit", state.blueCount, "Expert/platform findings", DecisionColor.BLUE, Icons.Default.Build)
            DashboardMetric("Limited evidence", state.grayCount, "AURA is abstaining", DecisionColor.GRAY, Icons.Default.Info)
            DashboardMetric("No action", state.greenCount, "Expected by current evidence", DecisionColor.GREEN, Icons.Default.CheckCircle)
        }
        Spacer(Modifier.height(8.dp))
        KeyValue("packages", state.assessments.size.toString())
        KeyValue("temporal episodes", state.temporalEpisodeCount.toString())
        KeyValue("defensive findings", state.defensiveFindingCount.toString())
        WhatChangedSummary(state)
    }
}

@Composable
private fun DashboardMetric(
    label: String,
    count: Int,
    description: String,
    color: DecisionColor,
    icon: ImageVector
) {
    Surface(
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier.widthIn(min = 148.dp)
    ) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = decisionTint(color))
                Text(
                    text = count.toString(),
                    modifier = Modifier.padding(start = 8.dp),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(label, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun WhatChangedSummary(state: AuraUiState) {
    val history = state.scanHistory ?: return
    Spacer(Modifier.height(8.dp))
    HorizontalDivider()
    Spacer(Modifier.height(8.dp))
    Text("What changed since last scan", style = MaterialTheme.typography.titleSmall)
    KeyValue("changed packages", history.packagesChangedSincePreviousScan.size.toString())
    KeyValue("new packages", history.packagesNewInThisScan.size.toString())
    KeyValue("removed packages", history.packagesRemovedSincePreviousScan.size.toString())
    val preview = (history.packagesChangedSincePreviousScan + history.packagesNewInThisScan)
        .take(4)
        .joinToString(", ")
    if (preview.isNotBlank()) {
        Text(
            text = preview,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun AppListHeader(
    state: AuraUiState,
    visibleAssessments: List<AuraAssessment>,
    mode: AudienceMode
) {
    Text(
        text = "App list (${visibleAssessments.size}/${state.assessments.size})",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold
    )
    Text(
        text = when (mode) {
            AudienceMode.BASIC -> "Showing user-actionable, technical, unknown, changed, or defensive-posture items first."
            AudienceMode.POWER -> "Showing apps with non-green decisions, active special access, defensive findings, or scan changes."
            AudienceMode.RESEARCH -> "Showing the first research-sorted package records from the full scan."
        },
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AssessmentRow(
    assessment: AuraAssessment,
    posture: DefensivePostureSummary?,
    episodeCount: Int,
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
                    text = humanDecisionLabel(assessment.decision.color),
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
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                TinyPill("role ${assessment.role.predicted}")
                TinyPill("prov ${assessment.provenance.provenanceClass}")
                if (episodeCount > 0) TinyPill("episodes $episodeCount")
                if (posture?.postureClass != null && posture.postureClass != DefensivePostureClass.NO_OBSERVED_WEAKNESS) {
                    TinyPill("posture ${posture.postureClass}")
                }
            }
        }
    }
}

@Composable
private fun AppDetailPanel(
    assessment: AuraAssessment,
    findings: List<DefensiveSurfaceFinding>,
    posture: DefensivePostureSummary?,
    episodes: List<TemporalEpisode>,
    state: AuraUiState,
    mode: AudienceMode
) {
    SectionSurface {
        AppDetailHeader(assessment, posture, findings, episodes)
        Spacer(Modifier.height(12.dp))
        UserRiskStoryPanel(assessment)
        RecommendedActionsList(assessment.decision.recommendedActions)
        WhatWasObservedPanel(assessment)
        if (posture?.postureClass?.let { it != DefensivePostureClass.NO_OBSERVED_WEAKNESS } == true || findings.isNotEmpty()) {
            DefensivePosturePanel(posture, findings, compact = mode == AudienceMode.BASIC)
        }

        if (mode != AudienceMode.BASIC) {
            HorizontalDivider(Modifier.padding(vertical = 12.dp))
            TechnicalSummaryPanel(assessment, posture, state)
            SpecialAccessPanel(assessment)
            TemporalEpisodePanel(episodes)
            RiskVectorBars(assessment)
        }

        if (mode == AudienceMode.RESEARCH) {
            HorizontalDivider(Modifier.padding(vertical = 12.dp))
            BaselineComparisonPanel(assessment)
            DecisionTraceSummary(assessment)
            CounterfactualPanel(assessment)
            ObservabilityPanel(assessment)
            EvidenceGraphSummary(assessment.evidenceGraph)
            EvidenceList(assessment.evidence)
            RawFeaturePanel(assessment)
        }
    }
}

@Composable
private fun AppDetailHeader(
    assessment: AuraAssessment,
    posture: DefensivePostureSummary?,
    findings: List<DefensiveSurfaceFinding>,
    episodes: List<TemporalEpisode>
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Default.Info, contentDescription = null, tint = decisionTint(assessment.decision.color))
        Column(Modifier.padding(start = 8.dp)) {
            Text(
                text = assessment.snapshot.appLabel.ifBlank { assessment.snapshot.packageName },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
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
        }
    }
    Spacer(Modifier.height(8.dp))
    KeyValue("threat decision", "${humanDecisionLabel(assessment.decision.color)} / ${assessment.decision.title}")
    KeyValue("primary alert", assessment.decision.userAlert.toString())
    KeyValue("technical finding", assessment.decision.expertFinding.toString())
    KeyValue("defensive posture", posture?.postureClass?.name ?: "NO_OBSERVED_WEAKNESS")
    KeyValue("episodes", episodes.size.toString())
    KeyValue("defensive findings", findings.size.toString())
}

@Composable
private fun UserRiskStoryPanel(assessment: AuraAssessment) {
    val story = assessment.userRiskStory
    Spacer(Modifier.height(4.dp))
    Text(story.headline, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
    Text(story.primaryReason, style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(6.dp))
    Text(story.whyItMatters, style = MaterialTheme.typography.bodySmall)
    Spacer(Modifier.height(6.dp))
    Text(
        text = "Recommended next step: ${story.recommendedNextStep}",
        style = MaterialTheme.typography.bodySmall,
        fontWeight = FontWeight.SemiBold
    )
    Text(
        text = "Confidence: ${story.confidenceText}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun WhatWasObservedPanel(assessment: AuraAssessment) {
    val story = assessment.userRiskStory
    Spacer(Modifier.height(12.dp))
    Text("What AURA observed", style = MaterialTheme.typography.titleSmall)
    if (story.whatWasObserved.isEmpty()) {
        Text("No high-priority observation was attached to the user story.", style = MaterialTheme.typography.bodySmall)
    } else {
        story.whatWasObserved.take(6).forEach { observed ->
            BulletText(observed)
        }
    }
    Spacer(Modifier.height(8.dp))
    Text("What AURA did not observe", style = MaterialTheme.typography.titleSmall)
    val notObserved = story.whatWasNotObserved.ifEmpty {
        listOf("AURA did not inspect screen contents, notification contents, TLS payloads, kernel state, baseband state, or TEE state.")
    }
    notObserved.take(5).forEach { item ->
        BulletText(item)
    }
    if (story.limitationsText.isNotBlank()) {
        Text(
            text = story.limitationsText,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun TechnicalSummaryPanel(
    assessment: AuraAssessment,
    posture: DefensivePostureSummary?,
    state: AuraUiState
) {
    Text("Technical summary", style = MaterialTheme.typography.titleSmall)
    KeyValue("role", "${assessment.role.predicted} (${scoreText(assessment.role.confidence)})")
    KeyValue("provenance", "${assessment.provenance.provenanceClass} (${scoreText(assessment.provenance.confidence)})")
    KeyValue("actionability", assessment.decision.actionabilityClass.name)
    KeyValue("installer", assessment.snapshot.installerPackageName ?: "none")
    KeyValue("source", assessment.snapshot.rawFeatures["sourcePartition"] ?: assessment.snapshot.sourceDir)
    KeyValue("collector", assessment.snapshot.collectorVersion)
    KeyValue("device", "${assessment.snapshot.deviceModel} API ${assessment.snapshot.apiLevel}")
    ChangeStatusPanel(assessment, state)
    posture?.let {
        KeyValue("defensive summary", it.userFacingSummary)
    }
}

@Composable
private fun ChangeStatusPanel(
    assessment: AuraAssessment,
    state: AuraUiState
) {
    val history = state.scanHistory ?: return
    val packageName = assessment.snapshot.packageName
    val changes = buildList {
        if (packageName in history.packagesChangedSincePreviousScan) add("changed since previous scan")
        if (packageName in history.packagesNewInThisScan) add("new in this scan")
        if (packageName in history.packagesRemovedSincePreviousScan) add("removed since previous scan")
    }
    KeyValue("scan change", changes.ifEmpty { listOf("no package-level diff") }.joinToString(", "))
}

@Composable
private fun SpecialAccessPanel(assessment: AuraAssessment) {
    if (assessment.snapshot.specialAccess.isEmpty()) return
    Spacer(Modifier.height(12.dp))
    Text("Special access states", style = MaterialTheme.typography.titleSmall)
    assessment.snapshot.specialAccess.toSortedMap().forEach { (name, state) ->
        KeyValue(name, state.name)
    }
}

@Composable
private fun TemporalEpisodePanel(episodes: List<TemporalEpisode>) {
    Spacer(Modifier.height(12.dp))
    Text("Temporal episodes", style = MaterialTheme.typography.titleSmall)
    if (episodes.isEmpty()) {
        Text("No temporal episode was attached to this app in the latest scan.", style = MaterialTheme.typography.bodySmall)
        return
    }
    episodes.forEach { episode ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${episode.type} ttl=${episode.ttlMillis / 60000}m",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(episode.explanation, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun RiskVectorBars(assessment: AuraAssessment) {
    Spacer(Modifier.height(12.dp))
    Text("Risk vector", style = MaterialTheme.typography.titleSmall)
    ScoreBar("harm", assessment.riskVector.harm)
    ScoreBar("legitimacy", assessment.riskVector.legitimacy)
    ScoreBar("abuse", assessment.riskVector.abuseEvidence)
    ScoreBar("prov trust", assessment.riskVector.provenanceTrust)
    ScoreBar("prov class", assessment.riskVector.provenanceConfidence)
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
private fun RecommendedActionsList(actions: List<RecommendedAction>) {
    if (actions.isEmpty()) return
    Spacer(Modifier.height(12.dp))
    Text("Recommended actions", style = MaterialTheme.typography.titleSmall)
    actions.take(6).forEach { action ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${action.scope} ${action.actionabilityClass}${if (action.destructive) " destructive" else ""}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(
            text = action.title,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold
        )
        Text(action.description, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun BaselineComparisonPanel(assessment: AuraAssessment) {
    val baseline = baselinePreview(assessment)
    Text("Baseline comparison", style = MaterialTheme.typography.titleSmall)
    KeyValue("permission-only", baseline.permissionOnly)
    KeyValue("capability-only", baseline.capabilityOnly)
    KeyValue("full AURA", assessment.decision.color.name)
    Text(
        text = baseline.explanation,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun DecisionTraceSummary(assessment: AuraAssessment) {
    val trace = assessment.decisionTrace
    Spacer(Modifier.height(12.dp))
    Text("Decision trace", style = MaterialTheme.typography.titleSmall)
    KeyValue("policy", trace.policyVersion)
    KeyValue("selected", trace.selectedDecision.name)
    KeyValue("matched rules", trace.evaluatedRules.count { it.matched }.toString())
    KeyValue("invariants", "${trace.invariantChecks.count { it.passed }}/${trace.invariantChecks.size}")
    trace.evaluatedRules.filter { it.matched }.take(4).forEach { rule ->
        Spacer(Modifier.height(4.dp))
        Text(
            text = rule.ruleId,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold
        )
        Text(rule.explanation, style = MaterialTheme.typography.bodySmall)
    }
    trace.rejectedAlternatives.take(3).forEach { alternative ->
        Spacer(Modifier.height(4.dp))
        Text(
            text = "not ${alternative.decisionColor}: ${alternative.reason}",
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun CounterfactualPanel(assessment: AuraAssessment) {
    val counterfactuals = assessment.decisionTrace.counterfactuals
    Spacer(Modifier.height(12.dp))
    Text("Counterfactual remediation", style = MaterialTheme.typography.titleSmall)
    if (counterfactuals.isEmpty()) {
        Text("No counterfactual changes were exported for this decision.", style = MaterialTheme.typography.bodySmall)
        return
    }
    counterfactuals.take(4).forEach { item ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "To reach ${item.targetDecision} (${if (item.userActionable) "user-actionable" else "not user-actionable"})",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold
        )
        item.requiredChanges.take(4).forEach { change ->
            BulletText(change)
        }
    }
}

@Composable
private fun ObservabilityPanel(assessment: AuraAssessment) {
    Spacer(Modifier.height(12.dp))
    Text("Observability contract", style = MaterialTheme.typography.titleSmall)
    val evidenceCounts = assessment.evidence
        .groupingBy { it.observabilityState }
        .eachCount()
        .toSortedMap(compareBy { it.name })
    evidenceCounts.forEach { (state, count) ->
        KeyValue(state.name, count.toString())
    }
    Text("No-root limits", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
    listOf(
        "No kernel, baseband, bootloader, TEE, or hidden OEM framework visibility.",
        "No screen contents, notification contents, keylogging, TLS MITM, or network payload inspection.",
        "Declared-only capability is not treated as active risky access."
    ).forEach { BulletText(it) }
}

@Composable
private fun EvidenceGraphSummary(graph: EvidenceGraph) {
    if (graph.nodes.isEmpty()) return
    Spacer(Modifier.height(12.dp))
    Text("Evidence graph", style = MaterialTheme.typography.titleSmall)
    KeyValue("nodes", graph.nodes.size.toString())
    KeyValue("edges", graph.edges.size.toString())
    graph.edges.take(10).forEach { edge ->
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
private fun EvidenceList(evidence: List<EvidenceItem>) {
    Spacer(Modifier.height(12.dp))
    Text("Evidence items", style = MaterialTheme.typography.titleSmall)
    evidence.take(10).forEach { item ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${item.source} ${scoreText(item.confidence)} ${item.observabilityState}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(item.humanExplanation, style = MaterialTheme.typography.bodySmall)
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
private fun DefensivePosturePanel(
    posture: DefensivePostureSummary?,
    findings: List<DefensiveSurfaceFinding>,
    compact: Boolean
) {
    Spacer(Modifier.height(12.dp))
    Text("Defensive posture", style = MaterialTheme.typography.titleSmall)
    Text(
        text = posture?.userFacingSummary ?: "No defensive-surface weakness was observed by the current metadata-only audit.",
        style = MaterialTheme.typography.bodySmall
    )
    if (findings.isEmpty()) return
    val findingLimit = if (compact) 3 else 8
    findings.take(findingLimit).forEach { finding ->
        Spacer(Modifier.height(6.dp))
        Text(
            text = "${finding.findingType} ${finding.severity} ${scoreText(finding.confidence)}",
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace
        )
        Text(finding.humanExplanation, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun RawFeaturePanel(assessment: AuraAssessment) {
    Spacer(Modifier.height(12.dp))
    Text("Raw feature preview", style = MaterialTheme.typography.titleSmall)
    assessment.snapshot.rawFeatures.toSortedMap().entries.take(18).forEach { (key, value) ->
        KeyValue(key, value)
    }
    KeyValue("requested permissions", assessment.snapshot.requestedPermissions.size.toString())
    KeyValue("granted permissions", assessment.snapshot.grantedPermissions.size.toString())
    KeyValue("components", assessment.snapshot.components.size.toString())
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
            modifier = Modifier.weight(0.36f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.64f),
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun BulletText(text: String) {
    Text(
        text = "- $text",
        style = MaterialTheme.typography.bodySmall,
        maxLines = 3,
        overflow = TextOverflow.Ellipsis
    )
}

@Composable
private fun TinyPill(text: String) {
    AssistChip(
        onClick = {},
        label = {
            Text(
                text = text,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    )
}

private data class BaselinePreview(
    val permissionOnly: String,
    val capabilityOnly: String,
    val explanation: String
)

private fun baselinePreview(assessment: AuraAssessment): BaselinePreview {
    val requested = assessment.snapshot.requestedPermissions
    val specialAccess = assessment.snapshot.specialAccess
    val dangerousPermissionCount = requested.count { permission ->
        val lower = permission.lowercase()
        listOf("camera", "record_audio", "location", "contacts", "sms", "phone", "install_packages", "alert_window")
            .any { it in lower }
    }
    val activeSpecialAccess = specialAccess.count { it.value == ObservabilityState.OBSERVED_ENABLED }
    val declaredSpecialAccess = specialAccess.count {
        it.value == ObservabilityState.DECLARED_ONLY || it.value == ObservabilityState.OBSERVED_ENABLED
    }
    val permissionOnly = when {
        dangerousPermissionCount + declaredSpecialAccess >= 3 -> "CRITICAL"
        dangerousPermissionCount + declaredSpecialAccess >= 1 -> "HIGH"
        else -> "LOW"
    }
    val capabilityOnly = when {
        activeSpecialAccess >= 2 -> "CRITICAL"
        assessment.riskVector.harm >= 0.70 -> "HIGH"
        assessment.riskVector.harm >= 0.40 -> "MEDIUM"
        else -> "LOW"
    }
    val explanation = when {
        permissionOnly in setOf("CRITICAL", "HIGH") && assessment.decision.color == DecisionColor.GREEN ->
            "A permission-only scanner would elevate this app because it has powerful capabilities; AURA lowers it because role fit, provenance context, abuse evidence, actionability, and uncertainty are evaluated separately."
        assessment.decision.color == DecisionColor.BLUE ->
            "AURA separates high exposure from panic: this is routed to expert/platform audit rather than the primary user-alert queue."
        assessment.decision.color == DecisionColor.RED ->
            "AURA escalates because powerful capability is paired with concrete abuse evidence, low role legitimacy, active risky access, and user-actionable remediation."
        assessment.decision.color == DecisionColor.GRAY ->
            "AURA abstains because unknown evidence is uncertainty, not maliciousness by itself."
        else ->
            "AURA uses the baseline signal as evidence, but the final decision depends on role, provenance, active state, actionability, and observability."
    }
    return BaselinePreview(permissionOnly, capabilityOnly, explanation)
}

private fun visibleAssessmentsForMode(
    state: AuraUiState,
    mode: AudienceMode
): List<AuraAssessment> {
    val changedPackages = buildSet {
        state.scanHistory?.packagesChangedSincePreviousScan?.let { addAll(it) }
        state.scanHistory?.packagesNewInThisScan?.let { addAll(it) }
    }
    val postureByPackage = state.defensivePostures.associateBy { it.packageName }
    val packagesWithFindings = state.defensiveSurfaceFindings.map { it.packageName }.toSet()
    fun AuraAssessment.isChangedOrDefensive(): Boolean =
        snapshot.packageName in changedPackages ||
            snapshot.packageName in packagesWithFindings ||
            postureByPackage[snapshot.packageName]?.postureClass?.let {
                it != DefensivePostureClass.NO_OBSERVED_WEAKNESS
            } == true

    fun AuraAssessment.hasActiveSpecialAccess(): Boolean =
        snapshot.specialAccess.values.any { it == ObservabilityState.OBSERVED_ENABLED }

    return when (mode) {
        AudienceMode.BASIC -> state.assessments
            .filter { it.decision.color != DecisionColor.GREEN || it.isChangedOrDefensive() }
            .ifEmpty { state.assessments.take(20) }
            .take(60)
        AudienceMode.POWER -> state.assessments
            .filter { it.decision.color != DecisionColor.GREEN || it.hasActiveSpecialAccess() || it.isChangedOrDefensive() }
            .ifEmpty { state.assessments.take(40) }
            .take(80)
        AudienceMode.RESEARCH -> state.assessments.take(160)
    }
}

private fun scoreText(value: Double): String = String.format(Locale.US, "%.2f", value)

private fun humanDecisionLabel(color: DecisionColor): String = when (color) {
    DecisionColor.RED -> "Action required"
    DecisionColor.YELLOW -> "Review"
    DecisionColor.BLUE -> "Technical audit"
    DecisionColor.GRAY -> "Limited evidence"
    DecisionColor.GREEN -> "No action"
}

@Composable
private fun decisionTint(color: DecisionColor): Color = when (color) {
    DecisionColor.RED -> MaterialTheme.colorScheme.error
    DecisionColor.YELLOW -> MaterialTheme.colorScheme.tertiary
    DecisionColor.BLUE -> MaterialTheme.colorScheme.primary
    DecisionColor.GRAY -> MaterialTheme.colorScheme.outline
    DecisionColor.GREEN -> MaterialTheme.colorScheme.secondary
}
