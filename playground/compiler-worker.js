// Import maps do not apply inside workers; use the packed browser entrypoint.
import { compile, check, symbolAt, completionsAt, version } from './pkg/index.js';

const methods = { compile, check, symbolAt, completionsAt, version };
self.onmessage = async ({ data: { id, method, args } }) => {
    try {
        if (!Object.hasOwn(methods, method)) throw new TypeError(`Unknown compiler method: ${method}`);
        self.postMessage({ id, result: await methods[method](...args) });
    } catch (error) {
        // A trap, such as a stack overflow, leaves this worker's instance unusable.
        const crashed = error instanceof WebAssembly.RuntimeError || error instanceof RangeError || error?.name === 'InternalError';
        self.postMessage({ id, error, crashed });
    }
};
