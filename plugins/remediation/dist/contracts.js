export class RemediationError extends Error {
    code;
    constructor(code) {
        super(`Remediation failed: ${code}`);
        this.code = code;
        this.name = 'RemediationError';
    }
}
