package com.maxwell.auth.service

import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

@Service
class RateLimitingService(
    @Value("\${app.security.rate-limit.max-requests}") private val maxRequests: Int,
    @Value("\${app.security.rate-limit.window-seconds}") private val windowSeconds: Long,
) {
    private data class Bucket(
        val count: AtomicInteger = AtomicInteger(0),
        val windowStart: Instant = Instant.now(),
    )

    private val buckets = ConcurrentHashMap<String, Bucket>()

    fun isAllowed(key: String): Boolean {
        val now = Instant.now()
        val bucket = buckets.compute(key) { _, existing ->
            when {
                existing == null -> Bucket()
                existing.windowStart.plusSeconds(windowSeconds).isBefore(now) -> Bucket()
                else -> existing
            }
        }!!
        return bucket.count.incrementAndGet() <= maxRequests
    }

    fun getRemainingRequests(key: String): Int {
        val bucket = buckets[key] ?: return maxRequests
        return maxOf(0, maxRequests - bucket.count.get())
    }

    @Scheduled(fixedDelay = 300_000)
    fun cleanupExpiredBuckets() {
        val now = Instant.now()
        buckets.entries.removeIf { (_, bucket) ->
            bucket.windowStart.plusSeconds(windowSeconds).isBefore(now)
        }
    }
}
