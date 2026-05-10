package cz.davidstrnadel.aura.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Science
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import cz.davidstrnadel.aura.core.AuraAssessment

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuraAppScreen(viewModel: AuraViewModel = viewModel()) {
    val state by viewModel.state.collectAsState()

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
            Text(
                text = "Role-normalized no-root assessment",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = "RED is user-actionable. BLUE is expert/platform audit relevance.",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.height(16.dp))

            when {
                state.loading -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator()
                    }
                }
                state.error != null -> {
                    Text("Scan failed: ${state.error}", color = MaterialTheme.colorScheme.error)
                }
                else -> {
                    SummaryRow(state)
                    Spacer(Modifier.height(16.dp))
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(state.assessments.take(30), key = { it.snapshot.packageName }) { assessment ->
                            AssessmentRow(assessment)
                        }
                        item {
                            Spacer(Modifier.height(12.dp))
                            if (state.exportPath.isNotBlank()) {
                                Text(
                                    text = "Last local export: ${state.exportPath}",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                                Spacer(Modifier.height(8.dp))
                            }
                            Text("JSON export preview", style = MaterialTheme.typography.titleSmall)
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = MaterialTheme.shapes.small,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = state.exportPreview,
                                    modifier = Modifier.padding(12.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }
        }
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
        AssistChip(onClick = {}, label = { Text("RED ${state.redCount}") })
        AssistChip(onClick = {}, label = { Text("BLUE ${state.blueCount}") })
        AssistChip(onClick = {}, label = { Text("GRAY ${state.grayCount}") })
        AssistChip(onClick = {}, label = { Text("YELLOW ${state.yellowCount}") })
        AssistChip(onClick = {}, label = { Text("GREEN ${state.greenCount}") })
        AssistChip(onClick = {}, label = { Text("DEF ${state.defensiveFindingCount}") })
    }
}

@Composable
private fun AssessmentRow(assessment: AuraAssessment) {
    Surface(
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Science, contentDescription = null)
                Text(
                    text = assessment.decision.color.name,
                    modifier = Modifier.padding(start = 8.dp),
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " ${assessment.decision.title}",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Text(assessment.snapshot.appLabel.ifBlank { assessment.snapshot.packageName })
            Text(
                text = assessment.snapshot.packageName,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = "role=${assessment.role.predicted} provenance=${assessment.provenance.provenanceClass}",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
