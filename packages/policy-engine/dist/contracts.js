export class PolicyError extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'PolicyError';
    }
}
