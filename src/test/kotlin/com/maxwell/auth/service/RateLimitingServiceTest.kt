package com.maxwell.auth.service

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RateLimitingServiceTest {

    private lateinit var service: RateLimitingService

    @BeforeEach
    fun setup() {
        service = RateLimitingService(maxRequests = 3, windowSeconds = 60)
    }

    @Test
    fun `allows requests within the configured limit`() {
        assertTrue(service.isAllowed("ip-a"))
        assertTrue(service.isAllowed("ip-a"))
        assertTrue(service.isAllowed("ip-a"))
    }

    @Test
    fun `blocks the request that exceeds the limit`() {
        repeat(3) { service.isAllowed("ip-b") }
        assertFalse(service.isAllowed("ip-b"))
    }

    @Test
    fun `limits are tracked independently per key`() {
        repeat(3) { service.isAllowed("ip-c") }
        assertFalse(service.isAllowed("ip-c"))
        assertTrue(service.isAllowed("ip-d"))
    }

    @Test
    fun `getRemainingRequests reflects consumed quota`() {
        service.isAllowed("ip-e")
        service.isAllowed("ip-e")
        assertEquals(1, service.getRemainingRequests("ip-e"))
    }
}
