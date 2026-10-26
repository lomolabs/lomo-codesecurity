declare module 'node:crypto' {
  type Hash = {
    update(value: string | Uint8Array, inputEncoding?: 'utf8'): Hash;
    digest(encoding: 'hex' | 'base64'): string;
  };

  export function createHash(algorithm: 'sha256'): Hash;
}

declare module 'node:path' {
  export const win32: Readonly<{
    isAbsolute(value: string): boolean;
    normalize(value: string): string;
    parse(value: string): Readonly<{ root: string }>;
    relative(from: string, to: string): string;
    join(...paths: string[]): string;
  }>;
}

declare module 'node:child_process' {
  type ChildProcess = {
    kill(signal?: 'SIGKILL' | 'SIGTERM'): boolean;
    readonly killed?: boolean;
    stdin?: {
      end(value?: string): void;
      destroy(): void;
      on(event: 'error', listener: (error: Error) => void): void;
    } | null;
  };
  type ExecFileError = Error & { code?: string | number; stderr?: string };
  export function execFile(
    file: string,
    args: readonly string[],
    options: Readonly<{ encoding: 'utf8'; maxBuffer: number; windowsHide: boolean; timeout?: number }>,
    callback: (error: ExecFileError | null, stdout: string, stderr: string) => void,
  ): ChildProcess;
  export function execFile(
    file: string,
    args: readonly string[],
    options: Readonly<{ encoding: 'buffer'; maxBuffer: number; windowsHide: boolean; timeout: number; env: NodeJS.ProcessEnv }>,
    callback: (error: ExecFileError | null, stdout: Buffer, stderr: Buffer) => void,
  ): ChildProcess;
}
