#define _GNU_SOURCE

#include "resizable_array.h"
#include <pthread.h>
#include <stdlib.h>
#include "lib.h"
#include "logger.h"
#include "tcp_spy.h"

///////////////////////////////////////////////////////////////////////////////

/*
  ___ _   _ _____ _____ ____  _   _    _    _          _    ____ ___
 |_ _| \ | |_   _| ____|  _ \| \ | |  / \  | |        / \  |  _ \_ _|
  | ||  \| | | | |  _| | |_) |  \| | / _ \ | |       / _ \ | |_) | |
  | || |\  | | | | |___|  _ <| |\  |/ ___ \| |___   / ___ \|  __/| |
 |___|_| \_| |_| |_____|_| \_\_| \_/_/   \_\_____| /_/   \_\_|  |___|

*/

// Variables
static pthread_mutex_t main_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static ELEM_TYPE *array = NULL; // Array of elements.
static pthread_mutex_t *mutex_array = NULL; // Array of mutexes.
static int size = 0;

// Private functions
static bool allocate_arrays(ELEM_TYPE **a_ptr, pthread_mutex_t **mutex_a_ptr,
                            int _size);
static bool init(int init_size);
static bool double_size(int index);
static bool is_index_valid(int index);

///////////////////////////////////////////////////////////////////////////////

static bool allocate_arrays(ELEM_TYPE **a_ptr, pthread_mutex_t **mutex_a_ptr,
                            int _size) {
        // Allocate new array for elements
        *a_ptr = (ELEM_TYPE *)calloc(1, sizeof(ELEM_TYPE) * _size);
        if (!*a_ptr) goto error;

        // Allocate new array for mutexes
        *mutex_a_ptr =
            (pthread_mutex_t *)my_malloc(sizeof(pthread_mutex_t) * _size);
        if (!*mutex_a_ptr) goto error;

        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

static bool init(int init_size) {
        // Init to max(init_size, MIN_INIT_SIZE)
        if (init_size < MIN_INIT_SIZE) init_size = MIN_INIT_SIZE;
        LOG(INFO, "Resizable array initialized to size %d.", init_size);

        // Allocate new arrays
        if (!allocate_arrays(&array, &mutex_array, init_size)) goto error;

        // Initialize new mutexes
        for (int i = 0; i < init_size; i++)
                if (!mutex_init(&mutex_array[i])) goto error;

        size = init_size;
        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

static bool double_size(int index) {
        // Compute new size
        int new_size, normal_new_size = size * GROWTH_FACTOR;
        new_size = normal_new_size > index+1 ? normal_new_size : index+1;
        LOG(INFO, "Resizable array doubling size to %d.", new_size);

        // Allocate new arrays
        ELEM_TYPE *new_a;
        pthread_mutex_t *new_mutex_a;
        if (!allocate_arrays(&new_a, &new_mutex_a, new_size)) goto error;

        // Copy elements
        for (int i = 0; i < size; i++) {
                new_a[i] = array[i];
                new_mutex_a[i] = mutex_array[i];
        }

        // Initialize new mutexes
        for (int i = size; i < new_size; i++)
                if (!mutex_init(&new_mutex_a[i])) goto error;

        // Free old array
        free(array);
        free(mutex_array);

        // Replace by new ones
        array = new_a;
        mutex_array = new_mutex_a;
        size = new_size;
        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

static bool is_index_valid(int index) {
        if (!array) goto error1;
        if (index > size - 1) goto error2;
        return true;
error1:
        LOG(ERROR, "Array uninitialized.")
        goto error_out;
error2:
        LOG(ERROR, "OOB (index %d, bound %d).", index, size - 1);
        goto error_out;
error_out:
        LOG_FUNC_FAIL;
        return false;
}

///////////////////////////////////////////////////////////////////////////////
/*
  ____  _   _ ____  _     ___ ____      _    ____ ___
 |  _ \| | | | __ )| |   |_ _/ ___|    / \  |  _ \_ _|
 | |_) | | | |  _ \| |    | | |       / _ \ | |_) | |
 |  __/| |_| | |_) | |___ | | |___   / ___ \|  __/| |
 |_|    \___/|____/|_____|___\____| /_/   \_\_|  |___|

*/
///////////////////////////////////////////////////////////////////////////////

bool ra_put_elem(int index, ELEM_TYPE elem) {
        mutex_lock(&main_mutex);
        if (!array && !init(index + 1)) goto error; // If NULL, initialize.
        if (index > size - 1 && !double_size(index)) goto error; // Should grow?
        mutex_lock(&mutex_array[index]);
        array[index] = elem;
        mutex_unlock(&mutex_array[index]);
        mutex_unlock(&main_mutex);
        return true;
error:
        mutex_unlock(&main_mutex);
        LOG_FUNC_FAIL;
        return false;
}

TcpConnection *ra_get_and_lock_elem(int index) {
        mutex_lock(&main_mutex);
        if (!array && !init(index + 1)) goto error; // If NULL, initialize.
        if (!is_index_valid(index)) goto error; // Validate index.
        if (!mutex_lock(&mutex_array[index])) goto error;
        TcpConnection *el = array[index];
        mutex_unlock(&main_mutex);
        return el;
error:
        mutex_unlock(&main_mutex);
        LOG_FUNC_FAIL;
        return NULL;
}

bool ra_unlock_elem(int index) {
        mutex_lock(&main_mutex);
        if (!is_index_valid(index)) goto error;
        if (!mutex_unlock(&mutex_array[index])) goto error;
        mutex_unlock(&main_mutex);
        return true;
error:
        mutex_unlock(&main_mutex);
        LOG_FUNC_FAIL;
        return false;
}

bool ra_is_present(int index) {
        mutex_lock(&main_mutex);
        bool ret = array && array[index];
        mutex_unlock(&main_mutex);
        return ret;
}

int ra_get_size(void) {
        mutex_lock(&main_mutex);
        int ret = size;
        mutex_unlock(&main_mutex);
        return ret;
}

void ra_free() {
        mutex_lock(&main_mutex);
        for (int i = 0; i < size; i++) {
                mutex_lock(&mutex_array[i]);
                FREE_ELEM(array[i]);
                mutex_unlock(&mutex_array[i]);
                mutex_destroy(&mutex_array[i]);
        }
        free(array);
        free(mutex_array);
        mutex_unlock(&main_mutex);
        mutex_destroy(&main_mutex);
}

void ra_reset(void) {
        mutex_lock(&main_mutex);
        ra_free();
        array = NULL;
        mutex_array = NULL;
        size = 0;
        mutex_unlock(&main_mutex);
}

