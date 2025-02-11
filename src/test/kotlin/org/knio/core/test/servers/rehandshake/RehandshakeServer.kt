package org.knio.core.test.servers.rehandshake

import org.knio.core.net.ssl.KSSLSocket
import org.knio.core.test.servers.TestServer
import java.io.ByteArrayOutputStream
import java.net.SocketException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * A server to test re-handshaking.
 */
class RehandshakeServer(
    private val serverSocket: SSLServerSocket
): TestServer, Runnable {

    override fun run() {
        while(!serverSocket.isClosed) {
            try {
                runClient(serverSocket.accept() as SSLSocket).start()
            } catch (e: SocketException) {
                // socket closed, probably
            }
        }
    }

    private fun runClient(client: SSLSocket) = Thread {
        client.use {
            while(!client.isClosed) {
                // handshake
                client.startHandshake()

                val str = client.read()
                client.write(str)

                client.session.invalidate()
            }
        }
    }.apply {
        isDaemon = true
    }

    override suspend fun start(): TestServer {
        Thread(this).start()
        return this
    }

    override suspend fun stop() {
        serverSocket.close()
    }

    override fun isSSL(): Boolean {
        return true
    }

    override fun getPort(): Int {
        return serverSocket.localPort
    }

    fun SSLSocket.write(str: String) {
        if(str.length > 255) {
            throw IllegalArgumentException("String is too long")
        }

        outputStream.write(str.length)
        outputStream.write(str.toByteArray(Charsets.UTF_8))
    }

    suspend fun KSSLSocket.write(str: String) {
        if(str.length > 255) {
            throw IllegalArgumentException("String is too long")
        }

        getOutputStream().write(str.length)
        getOutputStream().write(str.toByteArray(Charsets.UTF_8))
    }

    fun SSLSocket.read(): String {
        val length = inputStream.read()
        val buffer = ByteArray(length)
        inputStream.read(buffer)

        return String(buffer, Charsets.UTF_8)
    }

    suspend fun KSSLSocket.read(): String {
        val length = getInputStream().read()
        val buffer = ByteArray(length)
        getInputStream().read(buffer)

        return String(buffer, Charsets.UTF_8)
    }
}