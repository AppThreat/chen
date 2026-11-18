package io.appthreat.dataflowengineoss.queryengine

import io.appthreat.dataflowengineoss.queryengine.QueryEngineStatistics.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.util.concurrent.{CountDownLatch, Executors}

class QueryEngineStatisticsTests extends AnyWordSpec with Matchers:

  "QueryEngineStatistics" should {
      "start at zero for every key after a reset" in {
          QueryEngineStatistics.reset()
          QueryEngineStatistics.results() shouldBe Map(
            PATH_CACHE_HITS   -> 0L,
            PATH_CACHE_MISSES -> 0L
          )
      }

      "accept negative values" in {
          QueryEngineStatistics.reset()
          QueryEngineStatistics.incrementBy(PATH_CACHE_HITS, 5L)
          QueryEngineStatistics.incrementBy(PATH_CACHE_HITS, -2L)
          QueryEngineStatistics.results()(PATH_CACHE_HITS) shouldBe 3L
      }

      "report the exact total of increments made from many virtual threads" in {
          QueryEngineStatistics.reset()
          val threads    = 64
          val iterations = 20000
          val start      = new CountDownLatch(1)
          val executor   = Executors.newVirtualThreadPerTaskExecutor()
          try
            val futures = (0 until threads).map { _ =>
                executor.submit(new Runnable:
                  override def run(): Unit =
                    start.await()
                    var i = 0
                    while i < iterations do
                      QueryEngineStatistics.incrementBy(PATH_CACHE_HITS, 1L)
                      QueryEngineStatistics.incrementBy(PATH_CACHE_MISSES, 2L)
                      i += 1
                )
            }
            start.countDown()
            futures.foreach(_.get())
          finally executor.shutdown()
          val results = QueryEngineStatistics.results()
          results(PATH_CACHE_HITS) shouldBe threads.toLong * iterations
          results(PATH_CACHE_MISSES) shouldBe threads.toLong * iterations * 2
      }
  }
end QueryEngineStatisticsTests
