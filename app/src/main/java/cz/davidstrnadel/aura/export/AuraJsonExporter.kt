package cz.davidstrnadel.aura.export

import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import cz.davidstrnadel.aura.core.AuraAssessment
import cz.davidstrnadel.aura.core.DefensiveSurfaceFinding
import cz.davidstrnadel.aura.core.TemporalEpisode

@JsonClass(generateAdapter = true)
data class AuraScanExport(
    val schemaVersion: Int,
    val scanId: String,
    val generatedAt: Long,
    val flavor: String,
    val assessments: List<AuraAssessment>,
    val temporalEpisodes: List<TemporalEpisode>,
    val defensiveSurfaceFindings: List<DefensiveSurfaceFinding> = emptyList()
)

class AuraJsonExporter {
    private val moshi = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()

    private val adapter = moshi.adapter(AuraScanExport::class.java).indent("  ")

    fun toJson(export: AuraScanExport): String = adapter.toJson(export)
}
