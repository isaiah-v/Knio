package org.knio.core.io

import kotlinx.coroutines.sync.withLock
import org.knio.core.context.KnioContext
import org.knio.core.context.getKnioContext
import org.knio.core.lang.toCharBuffer
import java.io.IOException
import java.nio.CharBuffer
import kotlin.math.max
import kotlin.math.min

class KStringReader private constructor (
    str: String,
    context: KnioContext
): KReader(context) {

    companion object {
        suspend fun open(str: String): KStringReader {
            return KStringReader(str, getKnioContext())
        }
    }

    private var str: CharBuffer? = str.toCharBuffer()
    private var mark = 0


    /** Check to make sure that the stream has not been closed  */
    @Throws(IOException::class)
    private fun ensureOpen() {
        if (str == null) throw IOException("Stream closed")
    }

    @Throws(IOException::class)
    override suspend fun read(b: CharBuffer): Int = lock.withLock {
        ensureOpen()
        read0(b)
    }


    private suspend fun read0(b: CharBuffer): Int {
        val str = this.str!!

        val read = minOf(b.remaining(), str.remaining())
        if(read == 0) return -1

        b.put(b.position(), str, str.position(), read)

        str.position(str.position() + read)
        b.position(b.position() + read)

        return read
    }

    /**
     * Skips the specified number of characters in the stream. Returns
     * the number of characters that were skipped.
     *
     *
     * The `ns` parameter may be negative, even though the
     * `skip` method of the [Reader] superclass throws
     * an exception in this case. Negative values of `ns` cause the
     * stream to skip backwards. Negative return values indicate a skip
     * backwards. It is not possible to skip backwards past the beginning of
     * the string.
     *
     *
     * If the entire string has been read or skipped, then this method has
     * no effect and always returns 0.
     *
     * @exception  IOException  If an I/O error occurs
     */
    @Throws(IOException::class)
    override suspend fun skip(ns: Long): Long = lock.withLock {
        ensureOpen()
        return skip0(ns)
    }


    private suspend fun skip0(ns: Long): Long {
        val str = this.str!!
        val next = str.position()
        val length = str.limit()

        if (next >= length) return 0
        // Bound skip by beginning and end of the source
        var n = min((length - next).toDouble(), ns.toDouble()).toLong()
        n = max(-next.toDouble(), n.toDouble()).toLong()
        str.position((next + n).toInt())

        return n
    }

    /**
     * Tells whether this stream is ready to be read.
     *
     * @return True if the next read() is guaranteed not to block for input
     *
     * @exception  IOException  If the stream is closed
     */
    @Throws(IOException::class)
    override suspend fun ready(): Boolean = lock.withLock {
        ensureOpen()
        return true
    }

    /**
     * Tells whether this stream supports the mark() operation, which it does.
     */
    override suspend fun markSupported(): Boolean {
        return true
    }

    /**
     * Marks the present position in the stream.  Subsequent calls to reset()
     * will reposition the stream to this point.
     *
     * @param  readLimit  Limit on the number of characters that may be
     * read while still preserving the mark.  Because
     * the stream's input comes from a string, there
     * is no actual limit, so this argument must not
     * be negative, but is otherwise ignored.
     *
     * @exception  IllegalArgumentException  If `readAheadLimit < 0`
     * @exception  IOException  If an I/O error occurs
     */
    @Throws(IOException::class)
    override suspend fun mark(readLimit: Int) {
        require(readLimit >= 0) { "Read-ahead limit < 0" }

        lock.withLock(lock) {
            ensureOpen()
            mark = str!!.position()
        }
    }

    /**
     * Resets the stream to the most recent mark, or to the beginning of the
     * string if it has never been marked.
     *
     * @exception  IOException  If an I/O error occurs
     */
    @Throws(IOException::class)
    override suspend fun reset():Unit = lock.withLock {
        ensureOpen()
        str!!.position(mark)
    }

    /**
     * Closes the stream and releases any system resources associated with
     * it. Once the stream has been closed, further read(),
     * ready(), mark(), or reset() invocations will throw an IOException.
     * Closing a previously closed stream has no effect. This method will block
     * while there is another thread blocking on the reader.
     */
    override suspend fun close() =lock.withLock {
        str = null
    }
}