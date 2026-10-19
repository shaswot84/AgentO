export class A05Error extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'A05Error';
    }
}
