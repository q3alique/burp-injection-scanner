package com.burpinj.engine

enum class AttackMode(val label: String, val description: String) {
    SNIPER("Sniper", "One payload at a time, one position at a time (N × P requests)."),
    BATTERING_RAM("Battering ram", "The same payload placed into every position (P requests)."),
    PITCHFORK("Pitchfork", "One list per position, iterated in parallel (min(P1..Pn))."),
    CLUSTER_BOMB("Cluster bomb", "One list per position, cartesian product (P1 × … × Pn).")
}
