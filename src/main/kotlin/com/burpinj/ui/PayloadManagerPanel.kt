package com.burpinj.ui

import com.burpinj.payloads.PayloadClass
import com.burpinj.payloads.PayloadRepo
import com.burpinj.payloads.PayloadSet
import com.burpinj.payloads.Phase
import com.burpinj.payloads.TargetOs
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridLayout
import java.io.File
import javax.swing.*

/** Per-class checkbox + "Load wordlist…" controls. */
class PayloadManagerPanel : JPanel(BorderLayout()) {
    private val checks: Map<PayloadClass, JCheckBox>
    private val wordlists: MutableMap<PayloadClass, File?> = mutableMapOf()
    private val wordlistLabels: Map<PayloadClass, JLabel>
    private val phaseGroup = ButtonGroup()
    private val detection = JRadioButton("Detection sweep (light)", true)
    private val deep = JRadioButton("Deep test (expanded)")
    private val osGroup = ButtonGroup()
    private val osAny = JRadioButton("Both", true)
    private val osNix = JRadioButton("Linux")
    private val osWin = JRadioButton("Windows")
    private val collabCheck = JCheckBox("Use Burp Collaborator (OOB)", false)

    init {
        border = Theme.titled("Payload classes & wordlists")
        phaseGroup.add(detection); phaseGroup.add(deep)
        osGroup.add(osAny); osGroup.add(osNix); osGroup.add(osWin)

        val top = JPanel(GridLayout(0, 1, 0, 2))
        val phaseRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            add(JLabel("Phase:")); add(detection); add(deep)
        }
        val osRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            add(JLabel("OS target (filters RCE / Path proofs):"))
            add(osAny); add(osNix); add(osWin)
        }
        val collabRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            add(collabCheck)
            add(JLabel("— augments RCE/XXE/SSTI/CRLF with OOB probes").apply { foreground = Theme.fgMuted })
        }
        top.add(phaseRow); top.add(osRow); top.add(collabRow)
        add(top, BorderLayout.NORTH)

        // Single column — each row holds the class checkbox + wordlist controls inline.
        val grid = JPanel(GridLayout(0, 1, 0, 2))
        val checksB = mutableMapOf<PayloadClass, JCheckBox>()
        val labelsB = mutableMapOf<PayloadClass, JLabel>()
        for (klass in PayloadClass.values()) {
            val row = JPanel(BorderLayout(6, 0))
            val cb = JCheckBox(klass.label, true)
            val label = JLabel("built-in").apply { foreground = Theme.fgMuted }
            val load = JButton("Wordlist…").apply {
                margin = java.awt.Insets(1, 6, 1, 6)
                addActionListener {
                    val chooser = JFileChooser()
                    if (chooser.showOpenDialog(this@PayloadManagerPanel) == JFileChooser.APPROVE_OPTION) {
                        val f = chooser.selectedFile
                        wordlists[klass] = f
                        label.text = f.name
                    }
                }
            }
            val clear = JButton("×").apply {
                toolTipText = "Revert to built-in"
                margin = java.awt.Insets(1, 6, 1, 6)
                addActionListener {
                    wordlists[klass] = null
                    label.text = "built-in"
                }
            }
            val east = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
            east.add(label); east.add(load); east.add(clear)
            row.add(cb, BorderLayout.WEST); row.add(east, BorderLayout.EAST)
            grid.add(row)
            checksB[klass] = cb
            labelsB[klass] = label
        }
        checks = checksB
        wordlistLabels = labelsB
        add(JScrollPane(grid), BorderLayout.CENTER)
        preferredSize = Dimension(460, 320)
    }

    fun collaboratorEnabled(): Boolean = collabCheck.isSelected

    fun phase(): Phase = if (deep.isSelected) Phase.DEEP else Phase.DETECTION

    fun targetOs(): TargetOs = when {
        osNix.isSelected -> TargetOs.LINUX
        osWin.isSelected -> TargetOs.WINDOWS
        else -> TargetOs.ANY
    }

    fun selectedSets(): Map<PayloadClass, List<PayloadSet>> {
        val os = targetOs()
        val result = mutableMapOf<PayloadClass, List<PayloadSet>>()
        for ((klass, cb) in checks) {
            if (!cb.isSelected) continue
            val file = wordlists[klass]
            val set = if (file != null) PayloadRepo.fromFile(klass, phase(), file, os)
                      else PayloadRepo.builtIn(klass, phase(), os)
            if (set.payloads.isNotEmpty()) result[klass] = listOf(set)
        }
        return result
    }
}
