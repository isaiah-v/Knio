package org.knio.core.test.servers

interface TestServer {
    suspend fun start(): TestServer
    suspend fun stop()

    fun isSSL(): Boolean
    fun getPort(): Int
}
