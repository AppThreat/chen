package io.appthreat.php2atom.datastructures

class ArrayIndexTracker:
  private var currentValue = 0

  def next: String =
    val nextVal = currentValue
    currentValue += 1
    nextVal.toString

  def updateValue(newValue: Int): Unit =
      if newValue >= currentValue then
        currentValue = newValue + 1

object ArrayIndexTracker:
  def apply(): ArrayIndexTracker = new ArrayIndexTracker
