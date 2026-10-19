export class ReportingError extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'ReportingError';
    }
}
