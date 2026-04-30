package com.maxwell.auth.exception

class AccountLockedException(message: String) : RuntimeException(message)
class IpBlockedException(message: String) : RuntimeException(message)
class RateLimitExceededException(message: String) : RuntimeException(message)
class UserAlreadyExistsException(message: String) : RuntimeException(message)
class InvalidTokenException(message: String) : RuntimeException(message)
class UserNotFoundException(message: String) : RuntimeException(message)
class AccountNotEnabledException(message: String) : RuntimeException(message)
