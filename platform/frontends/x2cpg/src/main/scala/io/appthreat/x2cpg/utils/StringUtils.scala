package io.appthreat.x2cpg.utils

implicit class StringUtils(str: String):
    def isAllUpperCase: Boolean =
        str.forall(c => c.isUpper || !c.isLetter)
