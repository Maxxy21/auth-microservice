package com.maxwell.auth.controller

import com.maxwell.auth.dto.ApiResponse
import com.maxwell.auth.service.IpBlockingService
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
class AdminController(
    private val ipBlockingService: IpBlockingService,
) {
    @PostMapping("/block-ip/{ip}")
    fun blockIp(
        @PathVariable ip: String,
        @RequestParam(defaultValue = "Manual admin block") reason: String,
    ): ResponseEntity<ApiResponse> {
        ipBlockingService.blockIp(ip, reason)
        return ResponseEntity.ok(ApiResponse(true, "IP $ip blocked"))
    }

    @DeleteMapping("/block-ip/{ip}")
    fun unblockIp(@PathVariable ip: String): ResponseEntity<ApiResponse> {
        ipBlockingService.unblockIp(ip)
        return ResponseEntity.ok(ApiResponse(true, "IP $ip unblocked"))
    }
}
