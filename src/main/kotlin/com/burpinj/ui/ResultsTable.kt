package com.burpinj.ui

import burp.api.montoya.MontoyaApi
import com.burpinj.engine.JobResult
import java.awt.Color
import java.awt.Component
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter

class ResultsTable(private val api: MontoyaApi? = null) {

    private val cols = listOf("#", "Class", "Positions", "Payload", "Status", "Length", "Time (ms)", "Signals", "Confidence")
    private val rows = mutableListOf<JobResult>()

    val model = object : AbstractTableModel() {
        override fun getRowCount() = rows.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(c: Int) = cols[c]
        override fun getColumnClass(c: Int): Class<*> = when (c) {
            0, 4, 5, 6 -> java.lang.Integer::class.java
            8 -> java.lang.Double::class.java
            else -> String::class.java
        }
        override fun getValueAt(r: Int, c: Int): Any? {
            val row = rows[r]
            return when (c) {
                0 -> row.id
                1 -> row.klass.label
                2 -> row.positionLabels.joinToString(",")
                3 -> row.payloads.joinToString(" | ").take(120)
                4 -> row.response?.statusCode()?.toInt() ?: 0
                5 -> row.response?.body()?.length() ?: 0
                6 -> row.durationMs.toInt()
                7 -> signalSummary(row)
                8 -> row.confidence
                else -> ""
            }
        }
    }

    val table: JTable = JTable(model).apply {
        autoResizeMode = JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS
        rowHeight = 22
        gridColor = Theme.gridLine
        font = Theme.body
        tableHeader.font = Theme.h2
        fillsViewportHeight = true
        val sorter = TableRowSorter(model)
        sorter.toggleSortOrder(8)
        sorter.toggleSortOrder(8) // desc
        rowSorter = sorter

        // Confidence renderer (bar + percentage)
        getColumnModel().getColumn(8).cellRenderer = ConfidenceRenderer()
        // Class / signals get coloring too
        getColumnModel().getColumn(1).cellRenderer = ClassRenderer()
        getColumnModel().getColumn(7).cellRenderer = MutedRenderer()

        getColumnModel().getColumn(0).preferredWidth = 50
        getColumnModel().getColumn(1).preferredWidth = 110
        getColumnModel().getColumn(2).preferredWidth = 80
        getColumnModel().getColumn(3).preferredWidth = 340
        getColumnModel().getColumn(4).preferredWidth = 70
        getColumnModel().getColumn(5).preferredWidth = 70
        getColumnModel().getColumn(6).preferredWidth = 80
        getColumnModel().getColumn(7).preferredWidth = 220
        getColumnModel().getColumn(8).preferredWidth = 140

        componentPopupMenu = buildPopup()
        addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (e.isPopupTrigger) selectUnderMouse(e)
            }
            override fun mouseReleased(e: MouseEvent) {
                if (e.isPopupTrigger) selectUnderMouse(e)
            }
            private fun selectUnderMouse(e: MouseEvent) {
                val row = rowAtPoint(e.point)
                if (row >= 0 && !isRowSelected(row)) setRowSelectionInterval(row, row)
            }
        })
    }

    private fun buildPopup(): JPopupMenu {
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater").apply {
            addActionListener { selectedResults().forEach { api?.repeater()?.sendToRepeater(it.request) } }
        })
        menu.add(JMenuItem("Send to Intruder").apply {
            addActionListener { selectedResults().forEach { api?.intruder()?.sendToIntruder(it.request) } }
        })
        menu.add(JMenuItem("Send request to Comparer").apply {
            addActionListener {
                selectedResults().forEach { api?.comparer()?.sendToComparer(it.request.toByteArray()) }
            }
        })
        menu.add(JMenuItem("Send response to Comparer").apply {
            addActionListener {
                selectedResults().forEach { r ->
                    r.response?.let { api?.comparer()?.sendToComparer(it.toByteArray()) }
                }
            }
        })
        return menu
    }

    private fun selectedResults(): List<JobResult> {
        val sel = table.selectedRows
        return sel.toList().mapNotNull { rowAtView(it) }
    }

    fun snapshot(): List<JobResult> = rows.toList()

    fun add(row: JobResult) {
        SwingUtilities.invokeLater {
            rows.add(row)
            model.fireTableRowsInserted(rows.size - 1, rows.size - 1)
        }
    }

    fun clear() {
        SwingUtilities.invokeLater {
            val n = rows.size
            rows.clear()
            if (n > 0) model.fireTableRowsDeleted(0, n - 1)
        }
    }

    fun rowAtView(viewIdx: Int): JobResult? {
        if (viewIdx < 0) return null
        val modelIdx = table.convertRowIndexToModel(viewIdx)
        return rows.getOrNull(modelIdx)
    }

    private fun signalSummary(r: JobResult): String {
        val bits = mutableListOf<String>()
        if (r.signal.errorMatches.isNotEmpty()) bits += "err"
        if (r.signal.mathHit) bits += "math"
        if (r.signal.sensitiveHit) bits += "sens"
        if (r.signal.reflected) bits += "refl:${r.signal.reflectionContext ?: "?"}"
        if (r.signal.timingAnomaly) bits += "slow"
        if (r.signal.statusChanged) bits += "status"
        if (kotlin.math.abs(r.signal.lengthDelta) > 50) bits += "Δlen=${r.signal.lengthDelta}"
        if (r.error != null) bits += "ERR"
        return bits.joinToString(" · ")
    }

    private class ConfidenceRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSel: Boolean, hasFocus: Boolean, row: Int, col: Int
        ): Component {
            val c = (value as? Double) ?: 0.0
            val pct = (c * 100).toInt()
            text = "$pct%"
            horizontalAlignment = CENTER
            background = if (isSel) table.selectionBackground else blend(Theme.confidenceColor(c), Color(0x2B, 0x2B, 0x2B), 0.25f)
            foreground = Color.WHITE
            return this
        }
        private fun blend(a: Color, b: Color, t: Float): Color {
            val r = (a.red * t + b.red * (1 - t)).toInt()
            val g = (a.green * t + b.green * (1 - t)).toInt()
            val bl = (a.blue * t + b.blue * (1 - t)).toInt()
            return Color(r, g, bl)
        }
    }

    private class ClassRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSel: Boolean, hasFocus: Boolean, row: Int, col: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSel, hasFocus, row, col)
            foreground = if (isSel) table.selectionForeground else Theme.accent
            font = Theme.h2
            return this
        }
    }

    private class MutedRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSel: Boolean, hasFocus: Boolean, row: Int, col: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSel, hasFocus, row, col)
            foreground = if (isSel) table.selectionForeground else Theme.fgMuted
            return this
        }
    }
}
