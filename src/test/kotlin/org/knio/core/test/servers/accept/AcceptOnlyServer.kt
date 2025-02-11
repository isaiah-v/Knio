package org.knio.core.test.servers.accept

import org.knio.core.test.servers.TestServer
import java.lang.Thread.sleep
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

class AcceptOnlyServer(
    private val serverSocket: ServerSocket
): TestServer, Runnable {

    override fun run() {
        while(!serverSocket.isClosed) {
            try {
                runClient(serverSocket.accept()).start()
            } catch (e: SocketException) {
                // socket closed, probably
            }
        }
    }

    private fun runClient(client: Socket) = Thread {
        client.use {
            if (client is SSLSocket) {
                client.startHandshake()
            }

            // block until the client closes the connection, or until the client sends data
            client.getInputStream().read()
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
        return serverSocket is SSLServerSocket
    }

    override fun getPort(): Int {
        return serverSocket.localPort
    }
}