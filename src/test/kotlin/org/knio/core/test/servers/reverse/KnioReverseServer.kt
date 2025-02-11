package org.knio.core.test.servers.reverse

import kotlinx.coroutines.*
import org.knio.core.io.KInputStream
import org.knio.core.io.KOutputStream
import org.knio.core.lang.use
import org.knio.core.net.KServerSocket
import org.knio.core.net.KSocket
import org.knio.core.net.ssl.KSSLServerSocket
import org.knio.core.net.ssl.KSSLSocket
import org.knio.core.test.servers.TestServer
import java.net.SocketException
import javax.net.ssl.SSLSocket

/**
 * A server that reverses a string written using the classic Knio API.
 *
 * @property serverSocket The server socket to accept client connections.
 */
class KnioReverseServer(
    private val serverSocket: KServerSocket
): TestServer {

    /**
     * Starts the server and listens for client connections.
     * Reverses the input string from the client and sends it back.
     */
    private suspend fun run() = serverSocket.use {
        while (!serverSocket.isClosed()) {
            try {
                runClient(serverSocket.accept())
            } catch (e: SocketException) {
                // socket closed
            }
        }
    }

    private fun runClient(client: KSocket) = CoroutineScope(Dispatchers.Default).launch {
        client.use {
            if(client is SSLSocket) {
                client.startHandshake()
            }

            // read the input
            val input = readInput(client.getInputStream())
            client.shutdownInput()

            // reverse the input
            val reverse = input.reversed()

            // write the reversed input
            writeOutput(reverse, client.getOutputStream())
            client.shutdownOutput()
        }
    }

    /**
     * Reads the input from the given InputStream.
     *
     * @param input The InputStream to read from.
     * @return The string read from the input.
     */
    private suspend fun readInput(input: KInputStream): String {
        val buffer = ByteArray(1024)
        val builder = StringBuilder()

        while (true) {
            val read = input.read(buffer)
            if (read == -1) {
                break
            }

            builder.append(String(buffer, 0, read, Charsets.UTF_8))
        }

        return builder.toString()
    }

    /**
     * Writes the given string to the given OutputStream.
     *
     * @param str The string to write.
     * @param output The OutputStream to write to.
     */
    private suspend fun writeOutput(str: String, output: KOutputStream) {
        output.write(str.toByteArray(Charsets.UTF_8))
    }

    /**
     * Starts the server
     *
     * @return The instance of KnioReverseServer.
     */
    override suspend fun start(): KnioReverseServer {
        CoroutineScope(Dispatchers.Default).launch {
            run()
        }

        return this
    }

    override suspend fun stop() {
        serverSocket.close()
    }

    override fun isSSL(): Boolean {
        return serverSocket is KSSLServerSocket
    }

    override fun getPort(): Int {
        return runBlocking { serverSocket.getLocalPort() }
    }
}