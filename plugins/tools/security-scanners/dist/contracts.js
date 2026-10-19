export class ScannerError extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'ScannerError';
    }
}
