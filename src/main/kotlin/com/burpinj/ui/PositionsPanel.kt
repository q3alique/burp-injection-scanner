package com.burpinj.ui

import com.burpinj.engine.InsertionPoint
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import javax.swing.*

/** Shows current insertion points, lets the user remove them. */
class PositionsPanel : JPanel(BorderLayout()) {
    private val model = DefaultListModel<InsertionPoint>()
    private val list = JList(model).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                l: JList<*>?, value: Any?, index: Int, sel: Boolean, focus: Boolean
            ): java.awt.Component {
                val p = value as InsertionPoint
                val txt = "§${p.label}§  [${p.start}..${p.end}]  value=\"${p.originalValue.take(40)}\""
                return super.getListCellRendererComponent(l, txt, index, sel, focus)
            }
        }
    }
    private val removeBtn = JButton("Remove").apply { isEnabled = false }
    private val clearBtn = JButton("Clear all")

    init {
        border = Theme.titled("Insertion points (§pos§)")
        add(JScrollPane(list), BorderLayout.CENTER)
        val south = JPanel(FlowLayout(FlowLayout.RIGHT))
        south.add(removeBtn)
        south.add(clearBtn)
        add(south, BorderLayout.SOUTH)
        preferredSize = Dimension(360, 180)

        list.addListSelectionListener { removeBtn.isEnabled = list.selectedIndex >= 0 }
        removeBtn.addActionListener {
            val i = list.selectedIndex
            if (i >= 0) model.remove(i)
            relabel()
        }
        clearBtn.addActionListener {
            model.clear()
        }
    }

    fun add(p: InsertionPoint) {
        val label = "p${model.size() + 1}"
        model.addElement(p.copy(label = label))
    }

    fun positions(): List<InsertionPoint> = (0 until model.size()).map { model[it] }

    fun clear() = model.clear()

    private fun relabel() {
        val items = (0 until model.size()).map { model[it].copy(label = "p${it + 1}") }
        model.clear()
        items.forEach(model::addElement)
    }
}
