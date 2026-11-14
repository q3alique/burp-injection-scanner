package com.burpinj.ui

import java.awt.Color
import java.awt.Font
import javax.swing.BorderFactory
import javax.swing.border.Border

object Theme {
    val accent = Color(0xE8, 0x79, 0x22)         // Burp orange
    val accentDim = Color(0xC0, 0x66, 0x1C)
    val bgPanel = Color(0x2B, 0x2B, 0x2B)
    val bgField = Color(0x3C, 0x3F, 0x41)
    val fg = Color(0xE6, 0xE6, 0xE6)
    val fgMuted = Color(0xA0, 0xA0, 0xA0)
    val good = Color(0x3E, 0xB7, 0x6B)
    val warn = Color(0xE0, 0xA1, 0x2E)
    val bad = Color(0xD3, 0x4C, 0x4C)
    val gridLine = Color(0x3A, 0x3A, 0x3A)

    val mono: Font = Font(Font.MONOSPACED, Font.PLAIN, 12)
    val h1: Font = Font("Segoe UI", Font.BOLD, 15)
    val h2: Font = Font("Segoe UI", Font.BOLD, 13)
    val body: Font = Font("Segoe UI", Font.PLAIN, 12)

    fun pad(a: Int = 8, b: Int = 8, c: Int = 8, d: Int = 8): Border =
        BorderFactory.createEmptyBorder(a, b, c, d)

    fun titled(title: String): Border {
        val outer = BorderFactory.createLineBorder(gridLine, 1)
        val inner = BorderFactory.createEmptyBorder(6, 10, 10, 10)
        val titled = BorderFactory.createTitledBorder(outer, title)
        titled.titleFont = h2
        titled.titleColor = fg
        return BorderFactory.createCompoundBorder(titled, inner)
    }

    fun confidenceColor(c: Double): Color = when {
        c >= 0.75 -> bad
        c >= 0.45 -> warn
        c >= 0.20 -> accentDim
        else -> fgMuted
    }
}
