// Import maps do not apply inside workers; use the packed browser entrypoint.
import { compile, check, symbolAt, completionsAt, version } from './pkg/index.js';

const methods = { compile, check, symbolAt, completionsAt, version };
self.onmessage = async ({ data: { id, method, args } }) => {
    try {
        if (!Object.hasOwn(methods, method)) throw new TypeError(`Unknown compiler method: ${method}`);
        self.postMessage({ id, result: await methods[method](...args) });
    } catch (error) {
        self.postMessage({ id, error });
    }
};
