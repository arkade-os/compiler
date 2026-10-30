// Each load evaluates the glue again for a fresh instance.
exports.load = async () => {
    delete require.cache[require.resolve('./wasm/arkade_compiler.js')];
    return require('./wasm/arkade_compiler.js');
};
