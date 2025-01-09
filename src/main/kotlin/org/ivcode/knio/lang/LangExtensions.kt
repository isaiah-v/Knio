package org.ivcode.knio.lang

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

/**
 * Executes the given block function on this resource and then closes it.
 *
 * @param T the type of the resource
 * @param R the return type of the block function
 * @param block a function to process this resource
 * @return the result of the block function
 * @throws Exception if an error occurs during closing
 */
@Throws(Exception::class)
suspend inline fun <T : KAutoCloseable, R> T.use(block: (T) -> R): R {
    return try {
        block(this)
    } finally {
        close()
    }
}

@Throws(Exception::class)
suspend inline fun <T : KAutoCloseable, R> T.use(
    dispatcher: CoroutineDispatcher,
    crossinline block: suspend (T) -> R
): R = withContext(dispatcher) {
    return@withContext try {
        block(this@use)
    } finally {
        close()
    }
}

