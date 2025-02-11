package org.knio.core.test.servers.alpn

import org.knio.core.test.servers.TestServer
import java.io.OutputStream
import java.net.SocketException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket


class ALPNServer(
    private val serverSocket: SSLServerSocket
): TestServer, Runnable {

    override fun run() {

        serverSocket.use { serverSocket ->

            // Set ALPN protocols
            val sslParameters: SSLParameters = serverSocket.getSSLParameters()
            sslParameters.applicationProtocols = arrayOf("unsupported", "test")
            serverSocket.setSSLParameters(sslParameters)

            println("Server is listening on port 8443...")
            while (!serverSocket.isClosed) {
                try {
                    val socket = (serverSocket.accept() as SSLSocket)
                    runClient(socket).start()
                } catch (e: SocketException) {
                    // socket closed
                }
            }
        }
    }

    private fun runClient(clientSocket: SSLSocket) = Thread {
        clientSocket.use {
            clientSocket.startHandshake()
            println("Negotiated Protocol: " + clientSocket.getApplicationProtocol())

            // Write a response to the client
            val out: OutputStream = clientSocket.getOutputStream()
            out.write("Hello, secure world!".toByteArray())
            out.flush()
        }
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
}