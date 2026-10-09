class TaskQueue {
  constructor() {
    this.userTasks = new Map();
  }

  isBusy(userId) {
    return this.userTasks.has(userId) && this.userTasks.get(userId) === true;
  }

  async run(userId, fn) {
    if (this.userTasks.has(userId) && this.userTasks.get(userId) === true) {
      throw new Error('USER_BUSY');
    }

    this.userTasks.set(userId, true);

    try {
      const result = await fn();
      return result;
    } finally {
      this.userTasks.set(userId, false);
    }
  }

  runBackground(userId, fn, onSuccess, onError) {
    this.run(userId, fn)
      .then((result) => {
        if (onSuccess) onSuccess(result);
      })
      .catch((err) => {
        if (onError) onError(err);
      });
  }

  getStatus() {
    const busy = [];
    for (const [userId, isBusy] of this.userTasks.entries()) {
      if (isBusy) busy.push(userId);
    }
    return { busyUsers: busy, total: busy.length };
  }

  cleanup() {
    for (const [userId, isBusy] of this.userTasks.entries()) {
      if (!isBusy) {
        this.userTasks.delete(userId);
      }
    }
  }
}

const taskQueue = new TaskQueue();
setInterval(() => taskQueue.cleanup(), 60000);

module.exports = taskQueue;
