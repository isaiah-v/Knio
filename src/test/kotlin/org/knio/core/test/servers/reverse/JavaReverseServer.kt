package org.knio.core.test.servers.reverse

import org.knio.core.test.servers.TestServer
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * A server that reverses a string written using the classic Java API.
 *
 * @property serverSocket The server socket to accept client connections.
 */
class JavaReverseServer(
    private val serverSocket: ServerSocket
): Runnable, TestServer {

    /**
     * Starts the server and listens for client connections.
     * Reverses the input string from the client and sends it back.
     */
    override fun run() = serverSocket.use {
        while (!serverSocket.isClosed) {
            try {
                runClient(serverSocket.accept()).start()
            } catch (e: Throwable) {
                // socket closed
            }
        }
    }

    private fun runClient(client: Socket) = Thread {
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
    }.apply {
        isDaemon = true
    }

    /**
     * Reads the input from the given InputStream.
     *
     * @param input The InputStream to read from.
     * @return The string read from the input.
     */
    private fun readInput(input: InputStream): String {
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
    private fun writeOutput(str: String, output: OutputStream) {
        output.write(str.toByteArray(Charsets.UTF_8))
    }

    /**
     * Starts the server in a new daemon thread.
     *
     * @return The instance of JavaReverseServer.
     */
    override suspend fun start(): JavaReverseServer {
        val thead = Thread(this)
        thead.isDaemon = true
        thead.start()

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