export class A02Error extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
        this.name = 'A02Error';
    }
}
