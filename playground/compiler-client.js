let worker;
let nextId = 0;
const pending = new Map();

function fail(error) {
    worker.terminate();
    worker = undefined;
    for (const request of pending.values()) request.reject(error);
    pending.clear();
}

function call(method, ...args) {
    return new Promise((resolve, reject) => {
        if (!worker) {
            worker = new Worker(new URL('./compiler-worker.js', import.meta.url), { type: 'module' });
            worker.onmessage = ({ data: { id, result, error, crashed } }) => {
                if (crashed) return fail(error);
                const request = pending.get(id);
                if (!request) return;
                pending.delete(id);
                if (error) request.reject(error);
                else request.resolve(result);
            };
            worker.onerror = worker.onmessageerror = event => fail(new Error(event.message || 'Compiler worker communication failed'));
        }
        const id = ++nextId;
        pending.set(id, { resolve, reject });
        try {
            worker.postMessage({ id, method, args });
        } catch (error) {
            pending.delete(id);
            reject(error);
        }
    });
}

// One worker serializes compiler work; a pool is only needed for parallel throughput.
export const compile = (...args) => call('compile', ...args);
export const check = (...args) => call('check', ...args);
export const symbolAt = (...args) => call('symbolAt', ...args);
export const completionsAt = (...args) => call('completionsAt', ...args);
export const version = () => call('version');
