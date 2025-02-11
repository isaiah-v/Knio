package org.knio.core.net

import org.knio.core.lang.use
import org.knio.core.test.servers.TestServerTest
import org.knio.core.test.servers.accept.AcceptOnlyServer
import org.knio.core.test.servers.createJavaServerSocket
import org.knio.core.test.servers.createJavaSocket
import org.knio.core.test.servers.createKnioSocket
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.net.SocketTimeoutException

class ReadWriteTimoutTest: TestServerTest<AcceptOnlyServer>() {

    @ParameterizedTest
    @ValueSource(booleans = [false, true])
    fun `test read timeout`(isSSL: Boolean) = runServer(isSSL) {
        // java
        createJavaSocket().use { client ->
            client.soTimeout = 500

            assertThrows<SocketTimeoutException> {
                client.getInputStream().read()
            }
        }

        // knio
        createKnioSocket().use { client ->
            client.setReadTimeout(500)

            assertThrows<SocketTimeoutException> {
                client.getInputStream().read()
            }
        }
    }

    // XXX: How do I test write timeout?

    override suspend fun startReverseServer(isSSL: Boolean): AcceptOnlyServer {
        val server = AcceptOnlyServer(createJavaServerSocket(isSSL))
        server.start()

        return server
    }
}