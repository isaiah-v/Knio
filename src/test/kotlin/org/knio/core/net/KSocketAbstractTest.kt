package org.knio.core.net

import kotlinx.coroutines.runBlocking
import org.knio.core.lang.use
import org.knio.core.test.servers.*
import org.knio.core.test.servers.accept.AcceptOnlyServer
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import javax.net.SocketFactory
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class KSocketAbstractTest: TestServerTest<AcceptOnlyServer>() {

    @Test
    fun `set no-delay`(): Unit = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            socket.tcpNoDelay = true
            assertEquals(true, socket.tcpNoDelay)

            socket.tcpNoDelay = false
            assertEquals(false, socket.tcpNoDelay)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            socket.setTcpNoDelay(true)
            assertEquals(true, socket.getTcpNoDelay())

            socket.setTcpNoDelay(false)
            assertEquals(false, socket.getTcpNoDelay())
        }
    }

    @Test
    fun `set and get SO_KEEPALIVE`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            socket.keepAlive = true
            assertEquals(true, socket.keepAlive)

            socket.keepAlive = false
            assertEquals(false, socket.keepAlive)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            socket.setKeepAlive(true)
            assertEquals(true, socket.getKeepAlive())

            socket.setKeepAlive(false)
            assertEquals(false, socket.getKeepAlive())
        }
    }

    @Test
    fun `set and get SO_RCVBUF`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val bufferSize = 8192
            socket.receiveBufferSize = bufferSize
            assertEquals(bufferSize, socket.receiveBufferSize)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val bufferSize = 8192
            socket.setReceiveBufferSize(bufferSize)
            assertEquals(bufferSize, socket.getReceiveBufferSize())
        }
    }

    @Test
    fun `set and get SO_REUSEADDR`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            socket.reuseAddress = true
            assertEquals(true, socket.reuseAddress)

            socket.reuseAddress = false
            assertEquals(false, socket.reuseAddress)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            socket.setReuseAddress(true)
            assertEquals(true, socket.getReuseAddress())

            socket.setReuseAddress(false)
            assertEquals(false, socket.getReuseAddress())
        }
    }

    @Test
    fun `set and get SO_SNDBUF`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val bufferSize = 8192
            socket.sendBufferSize = bufferSize
            assertEquals(bufferSize, socket.sendBufferSize)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val bufferSize = 8192
            socket.setSendBufferSize(bufferSize)
            assertEquals(bufferSize, socket.getSendBufferSize())
        }
    }

    @Test
    fun `set and get read timeout`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val timeout = 500L
            socket.setReadTimeout(timeout)
            assertEquals(timeout, socket.getReadTimeout())
        }
    }

    @Test
    fun `set and unset read timeout`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)

            timeout = 0
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500L
            socket.setReadTimeout(timeout)
            assertEquals(timeout, socket.getReadTimeout())

            timeout = 0L
            socket.setReadTimeout(timeout)
            assertEquals(timeout, socket.getReadTimeout())
        }
    }

    @Test
    fun `set and unset read timeout 2`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)

            timeout = 0
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            var timeout: Long? = 500L
            socket.setReadTimeout(timeout)
            assertEquals(timeout, socket.getReadTimeout())

            timeout = 0L
            socket.setReadTimeout(null)
            assertEquals(timeout, socket.getReadTimeout())
        }
    }

    @Test
    fun `set negative read timeout`(): Unit = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val timeout = -1

            assertThrows<IllegalArgumentException> {
                socket.soTimeout = timeout
            }
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val timeout = -1L

            assertThrows<IllegalArgumentException> {
                socket.setReadTimeout(timeout)
            }
        }
    }

    @Test
    fun `set and get write timeout`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val timeout = 500L
            socket.setWriteTimeout(timeout)
            assertEquals(timeout, socket.getWriteTimeout())
        }
    }

    @Test
    fun `set and unset write timeout`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)

            timeout = 0
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500L
            socket.setWriteTimeout(timeout)
            assertEquals(timeout, socket.getWriteTimeout())

            timeout = 0L
            socket.setWriteTimeout(timeout)
            assertEquals(timeout, socket.getWriteTimeout())
        }
    }

    @Test
    fun `set and unset write timeout 2`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            var timeout = 500
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)

            timeout = 0
            socket.soTimeout = timeout
            assertEquals(timeout, socket.soTimeout)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            var timeout: Long? = 500L
            socket.setWriteTimeout(timeout)
            assertEquals(timeout, socket.getWriteTimeout())

            timeout = 0L
            socket.setWriteTimeout(null)
            assertEquals(timeout, socket.getWriteTimeout())
        }
    }

    @Test
    fun `set negative write timeout`(): Unit = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            val timeout = -1

            assertThrows<IllegalArgumentException> {
                socket.soTimeout = timeout
            }
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            val timeout = -1L

            assertThrows<IllegalArgumentException> {
                socket.setWriteTimeout(timeout)
            }
        }
    }

    @Test
    fun `set and get TCP_NODELAY`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            socket.tcpNoDelay = true
            assertEquals(true, socket.tcpNoDelay)

            socket.tcpNoDelay = false
            assertEquals(false, socket.tcpNoDelay)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            socket.setTcpNoDelay(true)
            assertEquals(true, socket.getTcpNoDelay())

            socket.setTcpNoDelay(false)
            assertEquals(false, socket.getTcpNoDelay())
        }
    }

    @Test
    fun `shutdown input`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            socket.shutdownInput()
            assertEquals(true, socket.isInputShutdown)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.shutdownInput()
            assertEquals(true, socket.isInputShutdown())
        }
    }

    @Test
    fun `shutdown output`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            socket.shutdownOutput()
            assertEquals(true, socket.isOutputShutdown)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.shutdownOutput()
            assertEquals(true, socket.isOutputShutdown())
        }
    }

    @Test
    fun `is bound when bound`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            assertEquals(true, socket.isBound)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(true, socket.isBound())
        }
    }

    @Test
    fun `is bound when not bound`() = runServer(false) {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound())
        }
    }

    @Test
    fun `test connect`() = runServer(false) {
        val address = InetSocketAddress("localhost", getPort())

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound)
            assertEquals(false, socket.isConnected)
            socket.connect(address)
            assertEquals(true, socket.isBound)
            assertEquals(true, socket.isConnected)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound())
            assertEquals(false, socket.isConnected())
            socket.connect(address)
            assertEquals(true, socket.isBound())
            assertEquals(true, socket.isConnected())
        }
    }

    @Test
    fun `test writing to shutdown output`() = runServer(false) {

        // Documentations states an IOException should be thrown
        // The IOException thrown is a SocketException

        // java
        createJavaSocket().use { client ->
            client.shutdownOutput()

            assertThrows<SocketException> {
                client.getOutputStream().write(0)
            }
        }

        // knio
        createKnioSocket().use { client ->
            client.shutdownOutput()

            assertThrows<SocketException> {
                client.getOutputStream().write(0)
            }
        }
    }

    @Test
    fun `get inet-address after close`() = runServer(false) {
        // java
        createJavaSocket().use { client ->
            client.close()
            assertNotNull(client.inetAddress)
        }

        // knio
        createKnioSocket().use { client ->
            client.close()
            assertNotNull(client.getInetAddress())
        }
    }

    @Test
    fun `get local address`() = runServer(false) {
        val expected = Inet4Address.getLoopbackAddress()

        // java
        createJavaSocket().use { socket ->
            assertEquals(expected, socket.localAddress)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(expected, socket.getLocalAddress())
        }
    }


    @Test
    fun `get local address before binding`() = runBlocking {
        val expected: InetAddress = Inet4Address.getByName("0.0.0.0")

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.localAddress)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.getLocalAddress())
        }
    }

    @Test
    fun `get local port`() = runServer(false) {
        val notExpected = -1

        // java
        createJavaSocket().use { socket ->
            assertNotEquals(notExpected, socket.localPort)
        }

        // knio
        createKnioSocket().use { socket ->
            assertNotEquals(notExpected, socket.getLocalPort())
        }
    }

    @Test
    fun `get local port before binding`() = runBlocking {
        val expected = UNDEFINED_LOCAL_PORT

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.localPort)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.getLocalPort())
        }
    }

    @Test
    fun `get local port after close`() = runServer(false) {
        val notExpected = -1

        // java
        createJavaSocket().use { socket ->
            socket.close()
            assertNotNull(socket.localPort)
            assertNotEquals(notExpected, socket.localPort)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.close()
            assertNotNull(socket.getLocalPort())
            assertNotEquals(notExpected, socket.getLocalPort())
        }
    }

    @Test
    fun `get local socket address`() = runServer(false) {
        val notExpected = InetSocketAddress(ANY_LOCAL_ADDRESS, 0)

        // java
        createJavaSocket().use { socket ->
            assertNotEquals(notExpected, socket.localSocketAddress)
        }

        // knio
        createKnioSocket().use { socket ->
            assertNotEquals(notExpected, socket.getLocalSocketAddress())
        }
    }

    @Test
    fun `get local socket address before binding`() = runBlocking {
        val expected = null

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.localSocketAddress)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.getLocalSocketAddress())
        }
    }

    @Test
    fun `get local socket address after close`() = runServer(false) {

        // java
        createJavaSocket().use { socket ->
            val openAddress = socket.localSocketAddress
            socket.close()
            assertNotNull(socket.localSocketAddress)
            assertEquals(InetSocketAddress(socket.localAddress,socket.localPort), socket.localSocketAddress)
            assertTrue(socket.localAddress.isAnyLocalAddress)
            assertNotEquals(openAddress, socket.localSocketAddress)
        }

        // knio
        createKnioSocket().use { socket ->
            val openAddress = socket.getLocalSocketAddress()
            socket.close()
            assertNotNull(socket.getLocalAddress())
            assertEquals(InetSocketAddress(socket.getLocalAddress(),socket.getLocalPort()), socket.getLocalSocketAddress())
            assertTrue(socket.getLocalAddress().isAnyLocalAddress)
            assertNotEquals(openAddress, socket.getLocalSocketAddress())
        }
    }

    @Test
    fun `get port`() = runServer(false) {
        val expected = getPort()

        // java
        createJavaSocket().use { socket ->
            assertEquals(expected, socket.port)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(expected, socket.getPort())
        }
    }

    @Test
    fun `get port before connecting`() = runBlocking {
        val expected = UNDEFINED_PORT

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.port)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.getPort())
        }
    }

    @Test
    fun `get port after close`() = runServer(false) {
        val expected = getPort()

        // java
        createJavaSocket().use { socket ->
            socket.close()
            assertNotNull(socket.port)
            assertEquals(expected, socket.port)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.close()
            assertNotNull(socket.getPort())
            assertEquals(expected, socket.getPort())
        }
    }

    @Test
    fun `get remote socket address`() = runServer(false) {
        val expected = InetSocketAddress("localhost", 8080)

        // java
        createJavaSocket().use { socket ->
            assertEquals(expected, socket.remoteSocketAddress)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(expected, socket.getRemoteSocketAddress())
        }
    }

    @Test
    fun `get remote socket address before connecting`() = runBlocking {
        val expected = null

        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.remoteSocketAddress)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(expected, socket.getRemoteSocketAddress())
        }
    }

    @Test
    fun `get remote socket address after close`() = runServer(false) {
        val expected = InetSocketAddress("localhost", 8080)

        // java
        createJavaSocket().use { socket ->
            socket.close()
            assertNotNull(socket.remoteSocketAddress)
            assertEquals(expected, socket.remoteSocketAddress)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.close()
            assertNotNull(socket.getRemoteSocketAddress())
            assertEquals(expected, socket.getRemoteSocketAddress())
        }
    }

    @Test
    fun `test negative receive buffer size`(): Unit = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertThrows<IllegalArgumentException> {
                socket.receiveBufferSize = -1
            }
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertThrows<IllegalArgumentException> {
                socket.setReceiveBufferSize(-1)
            }
        }
    }

    @Test
    fun `test isConnected`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            assertEquals(true, socket.isConnected)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(true, socket.isConnected())
        }
    }

    @Test
    fun `test isConnected before connecting`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isConnected)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isConnected())
        }
    }

    @Test
    fun `test isConnected after close`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            socket.close()
            // documentation states that isConnected should return true even after close
            assertEquals(true, socket.isConnected)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.close()
            assertEquals(true, socket.isConnected())
        }
    }

    @Test
    fun `test is bound`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            assertEquals(true, socket.isBound)
        }

        // knio
        createKnioSocket().use { socket ->
            assertEquals(true, socket.isBound())
        }
    }

    @Test
    fun `test is bound before connecting`() = runBlocking {
        // java
        SocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound)
        }

        // knio
        KSocketFactory.getDefault().createSocket().use { socket ->
            assertEquals(false, socket.isBound())
        }
    }

    @Test
    fun `test is bound after close`() = runServer(false) {
        // java
        createJavaSocket().use { socket ->
            socket.close()
            // documentation states that isBound should return true even after close
            assertEquals(true, socket.isBound)
        }

        // knio
        createKnioSocket().use { socket ->
            socket.close()
            assertEquals(true, socket.isBound())
        }
    }

    @Test
    fun `test bind`() = runBlocking {
        // java
        val javaSocket = SocketFactory.getDefault().createSocket()
        assertFalse(javaSocket.isBound)
        javaSocket.bind(InetSocketAddress("localhost", 0))
        assertTrue(javaSocket.isBound)

        // knio
        val knioSocket = KSocketFactory.getDefault().createSocket()
        assertFalse(knioSocket.isBound())
        knioSocket.bind(InetSocketAddress("localhost", 0))
        assertTrue(knioSocket.isBound())
    }

    @Test
    fun `test bind with null address`() = runBlocking {
        // java
        val javaSocket = SocketFactory.getDefault().createSocket()
        assertFalse(javaSocket.isBound)
        javaSocket.bind(null)
        assertTrue(javaSocket.isBound)

        // knio
        val knioSocket = KSocketFactory.getDefault().createSocket()
        assertFalse(knioSocket.isBound())
        knioSocket.bind(null)
        assertTrue(knioSocket.isBound())
    }

    override suspend fun startReverseServer(isSSL: Boolean): AcceptOnlyServer {
        val server = AcceptOnlyServer(createJavaServerSocket(isSSL))
        server.start()

        return server
    }
}