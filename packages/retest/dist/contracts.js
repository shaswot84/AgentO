export class RetestError extends Error {
    code;
    constructor(code) {
        super(`Retest failed: ${code}`);
        this.code = code;
        this.name = 'RetestError';
    }
}
