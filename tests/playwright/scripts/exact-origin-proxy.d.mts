export type ProxySnapshot = {
  requests: number; forwarded: number; denied: number; tunnelDenied: number;
  upgradeDenied: number; socketLimit: number; limitExceeded: boolean;
  upstreamFailed: number; timedOut: number; responseBytes: number; closed: boolean;
  limits: { requests: number; sockets: number; responseBytes: number; totalBytes: number; timeoutMs: number };
  activeSockets: number; activeUpstreams: number;
};
export function exactProxyOrigin(value: string): URL;
export function proxyTargetPath(origin: string, target: string, method: string, headers: Record<string, string>): string | null;
export function exactProxyContextOptions(proxyUrl: string, environment?: NodeJS.ProcessEnv): { server: string; bypass: string };
export function startExactOriginProxy(origin: string): Promise<{
  url: string; snapshot(): ProxySnapshot; close(): Promise<void>;
}>;
