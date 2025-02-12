package org.knio.core.net.ssl

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.knio.core.lang.use
import org.knio.core.test.servers.*
import org.knio.core.test.servers.rehandshake.RehandshakeServer

private const val PROTOCOL = "TLSv1.2"

/**
 * Tests for re-handshaking scenarios.
 *
 * @see RehandshakeServer
 */
class RehandshakeTest: TestServerTest<RehandshakeServer>() {

    @Test
    fun `test single handshake`() = runServer(true) {
        // Java
        createJavaSSLSocket(PROTOCOL).use { sslClient ->
            val expected = "hello world"

            sslClient.write(expected)
            val result = sslClient.read()

            assertEquals(expected, result)
        }

        // Knio
        createKnioSSLSocket(PROTOCOL).use { sslClient ->
            val expected = "hello world"

            sslClient.write(expected)
            val result = sslClient.read()

            assertEquals(expected, result)
        }
    }

    @Test
    fun `test multiple handshakes`() = runServer(true) {
        // on each iteration, the server will request a re-handshake

        // Java
        createJavaSSLSocket("TLSv1.2").use { sslClient ->
            val expectedList = listOf(
                "test 1",
                "test 2",
                "test 3",
                "test 4",
                "test 5",
            )

            for(expected in expectedList) {
                sslClient.write(expected)
                val result = sslClient.read()

                assertEquals(expected, result)
            }
        }


        // Knio
        createKnioSSLSocket("TLSv1.2").use { sslClient ->
            val expectedList = listOf(
                "test 1",
                "test 2",
                "test 3",
                "test 4",
                "test 5",
            )

            for(expected in expectedList) {
                println(expected)

                sslClient.write(expected)
                val result = sslClient.read()

                assertEquals(expected, result)
            }
        }
    }

    override suspend fun startReverseServer(isSSL: Boolean): RehandshakeServer {
        if(!isSSL) {
            throw IllegalArgumentException("SSL is required")
        }

        val server = RehandshakeServer(createJavaSSLServerSocket(PROTOCOL))
        server.start()

        return server
    }
}