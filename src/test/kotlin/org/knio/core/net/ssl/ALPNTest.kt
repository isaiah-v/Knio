package org.knio.core.net.ssl

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.knio.core.lang.use
import org.knio.core.test.servers.TestServerTest
import org.knio.core.test.servers.alpn.ALPNServer
import org.knio.core.test.servers.createJavaServerSocket
import org.knio.core.test.utils.createTestSSLContext
import java.net.InetSocketAddress
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLParameters
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ALPNTest: TestServerTest<ALPNServer>() {


    /**
     * TODO - valid use-case needed
     *
     * I can't get [SSLSocket.setHandshakeApplicationProtocolSelector] to get called in
     * Knio using the `SSLEngine` or in Java using the `SSLSocket`. The documentation for
     * [SSLSocket.setHandshakeApplicationProtocolSelector] states that it overrides the
     * [SSLParameters.setApplicationProtocols], but it doesn't seem to. Even if not
     * explicitly set, it default to the empty-string value. Setting it to `null` throws
     * an exception.
     *
     * Not sure how often this is used in practice. Theres no good information online
     * that I could find.
     */
    //@Test
    fun `get application protocol with selector function`()  = runServer(true) {
        // java
        createTestSSLContext().socketFactory.createSocket().use { client ->
            val sslClient = client as SSLSocket

            sslClient.setHandshakeApplicationProtocolSelector { _, _ -> "test" }

            assertNull(sslClient.applicationProtocol) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.applicationProtocol) // before handshake
            sslClient.startHandshake()

            // after handshake
            assertEquals("test", sslClient.applicationProtocol)
        }

        // knio
        createTestSSLContext().getKnioSSLSocketFactory().createSocket().use { client ->
            val sslClient = client as KSSLSocket

            sslClient.setHandshakeApplicationProtocolSelector { _, _ -> "test" }

            assertNull(sslClient.getApplicationProtocol()) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.getApplicationProtocol()) // before handshake
            sslClient.startHandshake()

            // after handshake
            assertEquals("test", sslClient.getApplicationProtocol())
        }
    }

    @Test
    fun `negotiate ALPN protocol`():Unit = runServer(true) {
        // java
        createTestSSLContext().socketFactory.createSocket().use { client ->
            val sslClient = client as SSLSocket

            sslClient.sslParameters = SSLParameters().apply {
                applicationProtocols = arrayOf("test")
            }

            assertNull(sslClient.applicationProtocol) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.applicationProtocol) // before handshake
            sslClient.startHandshake()

            // after handshake
            assertEquals("test", sslClient.applicationProtocol)
        }

        // knio
        createTestSSLContext().getKnioSSLSocketFactory().createSocket().use { client ->
            val sslClient = client as KSSLSocket

            sslClient.setSSLParameters(SSLParameters().apply {
                applicationProtocols = arrayOf("test")
            })

            assertNull(sslClient.getApplicationProtocol()) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.getApplicationProtocol()) // before handshake
            sslClient.startHandshake()

            // after handshake
            assertEquals("test", sslClient.getApplicationProtocol())
        }
    }

    @Test
    fun `fail to negotiate ALPN protocol`():Unit = runServer(true) {
        // java
        createTestSSLContext().socketFactory.createSocket().use { client ->
            val sslClient = client as SSLSocket

            sslClient.sslParameters = SSLParameters().apply {
                applicationProtocols = arrayOf("none that you got")
            }

            assertNull(sslClient.applicationProtocol) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.applicationProtocol) // before handshake

            assertThrows<SSLHandshakeException> {
                sslClient.startHandshake()
            }
        }

        // knio
        createTestSSLContext().getKnioSSLSocketFactory().createSocket().use { client ->
            val sslClient = client as KSSLSocket

            sslClient.setSSLParameters(SSLParameters().apply {
                applicationProtocols = arrayOf("none that you got")
            })

            assertNull(sslClient.getApplicationProtocol()) // before connect
            sslClient.connect(InetSocketAddress("localhost", getPort()))

            assertNull(sslClient.getApplicationProtocol()) // before handshake
            assertThrows<SSLHandshakeException> {
                sslClient.startHandshake()
            }
        }
    }



    override suspend fun startReverseServer(isSSL: Boolean): ALPNServer {
        if(!isSSL) {
            throw IllegalArgumentException("SSL is required")
        }

        val server = ALPNServer(createJavaServerSocket(true) as SSLServerSocket)
        server.start()

        return server
    }
}