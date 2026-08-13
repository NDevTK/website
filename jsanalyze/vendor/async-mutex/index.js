// async-mutex — vendored dependency of vendor/z3-solver.
//
// z3-solver's high-level API serialises every `check()` through a
// mutex (`vendor/z3-solver/high-level/high-level.js`) because the
// Z3 WASM build keeps a single global solving context: two
// overlapping `check()` calls corrupt each other's state. The
// upstream npm tarball declares `async-mutex` as a runtime
// dependency but the vendored tree only carried z3-solver itself,
// so `require('async-mutex')` threw MODULE_NOT_FOUND in Node and
// Z3 never initialised. The browser path was unaffected because
// `browser.esm.js` was esbuild-bundled at vendor time with
// async-mutex inlined.
//
// This file is the missing half of that vendoring: a port of
// async-mutex 0.5.0 (MIT, https://github.com/DirtyHairy/async-mutex)
// to modern JavaScript. The published package ships ES5 output
// with a tslib dependency; the semantics below are the same, just
// written against native async/await so the vendored tree stays
// dependency-free.
//
// Semantics preserved from upstream:
//
//   * `acquire()` resolves in FIFO order; a ticket is
//     `[value, release]` for Semaphore and bare `release` for Mutex.
//   * `release` is idempotent — calling it twice releases once.
//   * `runExclusive` releases in a `finally`, so a throwing
//     callback still frees the lock and the error propagates.
//   * `cancel()` rejects every queued (not yet dispatched) ticket
//     with the cancel error; already-acquired holders keep theirs.
//   * `waitForUnlock()` resolves immediately when unlocked.

'use strict';

const E_TIMEOUT = new Error('timeout while waiting for mutex to become available');
const E_ALREADY_LOCKED = new Error('mutex already locked');
const E_CANCELED = new Error('request for lock canceled');

class Semaphore {
  constructor(maxConcurrency, cancelError = E_CANCELED) {
    if (maxConcurrency <= 0) {
      throw new Error('semaphore must be initialized to a positive value');
    }
    this._maxConcurrency = maxConcurrency;
    this._cancelError = cancelError;
    this._value = maxConcurrency;
    this._queue = [];
    this._waiters = [];
    this._currentReleaser = undefined;
  }

  acquire() {
    const locked = this.isLocked();
    const ticket = new Promise((resolve, reject) => {
      this._queue.push({ resolve, reject });
    });
    if (!locked) this._dispatch();
    return ticket;
  }

  async runExclusive(callback) {
    const [value, release] = await this.acquire();
    try {
      return await callback(value);
    } finally {
      release();
    }
  }

  waitForUnlock() {
    if (!this.isLocked()) return Promise.resolve();
    return new Promise((resolve) => { this._waiters.push({ resolve }); });
  }

  isLocked() {
    return this._value <= 0;
  }

  release() {
    if (this._maxConcurrency > 1) {
      throw new Error(
        'this method is unavailable on semaphores with concurrency > 1; ' +
        'use the scoped release returned by acquire instead');
    }
    if (this._currentReleaser) {
      const releaser = this._currentReleaser;
      this._currentReleaser = undefined;
      releaser();
    }
  }

  cancel() {
    for (const ticket of this._queue) ticket.reject(this._cancelError);
    this._queue = [];
  }

  _dispatch() {
    const next = this._queue.shift();
    if (!next) return;
    let released = false;
    this._currentReleaser = () => {
      if (released) return;
      released = true;
      this._value++;
      this._resolveWaiters();
      this._dispatch();
    };
    next.resolve([this._value--, this._currentReleaser]);
  }

  _resolveWaiters() {
    for (const waiter of this._waiters) waiter.resolve();
    this._waiters = [];
  }
}

class Mutex {
  constructor(cancelError) {
    this._semaphore = new Semaphore(1, cancelError);
  }

  async acquire() {
    const [, releaser] = await this._semaphore.acquire();
    return releaser;
  }

  runExclusive(callback) {
    return this._semaphore.runExclusive(() => callback());
  }

  isLocked() {
    return this._semaphore.isLocked();
  }

  waitForUnlock() {
    return this._semaphore.waitForUnlock();
  }

  release() {
    this._semaphore.release();
  }

  cancel() {
    return this._semaphore.cancel();
  }
}

// withTimeout — wrap a Mutex/Semaphore so acquisition rejects with
// `timeoutError` once `timeout` ms elapse. A ticket that arrives
// after the deadline is released immediately so the lock isn't
// leaked to a caller that already gave up.
function withTimeout(sync, timeout, timeoutError = E_TIMEOUT) {
  return {
    acquire() {
      return new Promise((resolve, reject) => {
        let timedOut = false;
        const handle = setTimeout(() => {
          timedOut = true;
          reject(timeoutError);
        }, timeout);
        sync.acquire().then(
          (ticket) => {
            if (timedOut) {
              const release = Array.isArray(ticket) ? ticket[1] : ticket;
              release();
              return;
            }
            clearTimeout(handle);
            resolve(ticket);
          },
          (err) => {
            if (timedOut) return;
            clearTimeout(handle);
            reject(err);
          },
        );
      });
    },

    async runExclusive(callback) {
      let release = () => undefined;
      try {
        const ticket = await this.acquire();
        if (Array.isArray(ticket)) {
          release = ticket[1];
          return await callback(ticket[0]);
        }
        release = ticket;
        return await callback();
      } finally {
        release();
      }
    },

    release() {
      sync.release();
    },

    cancel() {
      return sync.cancel();
    },

    waitForUnlock(weight) {
      return new Promise((resolve, reject) => {
        const handle = setTimeout(() => reject(timeoutError), timeout);
        sync.waitForUnlock(weight).then(() => {
          clearTimeout(handle);
          resolve();
        });
      });
    },

    isLocked() {
      return sync.isLocked();
    },
  };
}

// tryAcquire — acquire without waiting: reject with
// `alreadyAcquiredError` if the lock is not immediately free.
function tryAcquire(sync, alreadyAcquiredError = E_ALREADY_LOCKED) {
  return withTimeout(sync, 0, alreadyAcquiredError);
}

module.exports = {
  Semaphore,
  Mutex,
  withTimeout,
  tryAcquire,
  E_TIMEOUT,
  E_ALREADY_LOCKED,
  E_CANCELED,
};
