const { decrypt } = require('./pkg/rijndael_256_wasm');

const kBase64 = 'VWZJhnG33pMKTzI3P5Sikoj6RL2G/4NFStXrzcUYWXw=';
const ivBase64 = 'ODMyMDYyNzQzNDI1OTA3ODU4MjIzMjY0ODM1MTYwNjg=';
const encryptedBase64 =
    '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';
const expectedBase64 =
    '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\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000';

try {
    console.time('decrypt chunk');
    const result = decrypt(
        kBase64,
        ivBase64,
        encryptedBase64
    );
    console.timeEnd('decrypt chunk');
    console.log(result === expectedBase64);
} catch (error) {
    console.log(error.message());
}
