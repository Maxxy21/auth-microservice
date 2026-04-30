package com.maxwell.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class AuthMicroserviceApplication

fun main(args: Array<String>) {
    runApplication<AuthMicroserviceApplication>(*args)
}
