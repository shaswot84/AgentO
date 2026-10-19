/** One bounded hunk per file, retaining three context lines at both ends. */
export declare function unifiedDiff(path: string, before: string, after: string): string;
