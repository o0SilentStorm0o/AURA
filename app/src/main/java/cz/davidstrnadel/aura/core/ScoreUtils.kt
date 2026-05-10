package cz.davidstrnadel.aura.core

fun Double.clampedScore(): Double = coerceIn(0.0, 1.0)

fun Boolean.asScore(): Double = if (this) 1.0 else 0.0
