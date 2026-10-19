export class A01Error extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'A01Error';
    }
}
