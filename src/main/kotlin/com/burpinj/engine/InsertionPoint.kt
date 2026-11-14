package com.burpinj.engine

/** A byte-offset range inside the raw request marking an insertion point. */
data class InsertionPoint(
    val start: Int,
    val end: Int,
    val originalValue: String,
    val label: String = "pos"
) {
    val length: Int get() = end - start
}
