#define _GNU_SOURCE

#include "resizable_array.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"
#include "logger.h"
#include "tcp_events.h"

typedef struct {
        ELEM_TYPE elem;
        pthread_mutex_t mutex;
} ElemWrapper;

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static ElemWrapper **array = NULL;
static int size = 0;

// Private functions

ElemWrapper **allocate_array(int _size) {
        return (ElemWrapper **)my_calloc(1, sizeof(ElemWrapper *) * _size);
}

static bool init(int init_size) {
        if (init_size < MIN_INIT_SIZE) init_size = MIN_INIT_SIZE;
        LOG(INFO, "Resizable array initialized to size %d.", init_size);
        if (!(array = allocate_array(init_size))) goto error;
        size = init_size;
        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

static bool double_size(int index) {
        // Compute new size
        int new_size, normal_new_size = size * GROWTH_FACTOR;
        new_size = normal_new_size > index + 1 ? normal_new_size : index + 1;
        LOG(INFO, "Resizable array doubling size to %d.", new_size);

        ElemWrapper **new_a;
        if (!(new_a = allocate_array(new_size))) goto error;

        for (int i = 0; i < size; i++) new_a[i] = array[i];

        free(array);
        array = new_a;
        size = new_size;
        return true;
error:
        LOG_FUNC_FAIL;
        return false;
}

static bool is_index_in_bounds(int index) { return index < size; }

/* Public functions */

bool ra_put_elem(int index, ELEM_TYPE elem) {
        pthread_rwlock_wrlock(&rwlock);
        if (!array && !init(index + 1)) goto error;
        if (index > size - 1 && !double_size(index))
                goto error;

        ElemWrapper *ew = (ElemWrapper *)my_malloc(sizeof(ElemWrapper));
        if (!ew) goto error;
        mutex_init(&ew->mutex);
        ew->elem = elem;

        array[index] = ew;
        pthread_rwlock_unlock(&rwlock);
        return true;
error:
        pthread_rwlock_unlock(&rwlock);
        LOG_FUNC_FAIL;
        return false;
}

ELEM_TYPE ra_get_and_lock_elem(int index) {
        pthread_rwlock_rdlock(&rwlock);
        if (!is_index_in_bounds(index)) goto error;
        if (!array[index]) {
                pthread_rwlock_unlock(&rwlock);
                return NULL;
        }
        ElemWrapper *ew = array[index];
        mutex_lock(&ew->mutex);
        return ew->elem;
error:
        LOG(ERROR, "OOB (index %d, bound %d).", index, size - 1);
        pthread_rwlock_unlock(&rwlock);
        LOG_FUNC_FAIL;
        return NULL;
}

void ra_unlock_elem(int index) {
        if (!is_index_in_bounds(index)) goto error1;
        if (!array[index]) goto error2;
        mutex_unlock(&(array[index]->mutex));
        pthread_rwlock_unlock(&rwlock);
        return;
error1:
        LOG(ERROR, "OOB (index %d, bound %d).", index, size - 1);
        goto error_out;
error2:
        LOG(ERROR, "No item at index %d.", index);
error_out:
        pthread_rwlock_unlock(&rwlock);
        LOG_FUNC_FAIL;
}

ELEM_TYPE ra_remove_elem(int index) {
        pthread_rwlock_wrlock(&rwlock);
        if (!is_index_in_bounds(index)) goto error;
        if (!array[index]) {
                pthread_rwlock_unlock(&rwlock);
                return NULL;
        }
        ElemWrapper *ew = array[index];
        // No need to lock it. Having the rwlock in write mode means no other
        // thread has a valid el or will be able to acquire one.
        mutex_destroy(&ew->mutex);
        ELEM_TYPE el = ew->elem;
        array[index] = NULL;
        free(ew);
        pthread_rwlock_unlock(&rwlock);
        return el;
error:
        LOG(ERROR, "OOB (index %d, bound %d).", index, size - 1);
        pthread_rwlock_unlock(&rwlock);
        LOG_FUNC_FAIL;
        return NULL;
}

bool ra_is_present(int index) {
        pthread_rwlock_rdlock(&rwlock);
        if (!is_index_in_bounds(index)) goto out_false;
        bool ret = (array[index] != NULL);
        pthread_rwlock_unlock(&rwlock);
        return ret;
out_false:
        pthread_rwlock_unlock(&rwlock);
        return false;
}

int ra_get_size(void) {
        pthread_rwlock_rdlock(&rwlock);
        int ret = size;
        pthread_rwlock_unlock(&rwlock);
        return ret;
}

void ra_free() {
        pthread_rwlock_rdlock(&rwlock);
        for (int i = 0; i < size; i++) {
                if (array[i]) {
                        mutex_destroy(&array[i]->mutex);
                        FREE_ELEM(array[i]->elem);
                        free(array[i]);
                }
        }
        free(array);
        pthread_rwlock_unlock(&rwlock);
        pthread_rwlock_destroy(&rwlock);
}

void ra_reset(void) {
        if (pthread_rwlock_init(&rwlock, NULL)) {
                LOG(ERROR, "pthread_rwlock_init() failed. %s.",
                    strerror(errno));
        }
        array = NULL;
        size = 0;
}
