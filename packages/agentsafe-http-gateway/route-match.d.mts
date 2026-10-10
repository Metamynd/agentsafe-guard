// Type declarations for @metamynd/agentsafe-http-gateway/route-match (route-match.mjs).
import type { Route } from './gateway.mjs';

export function segments(path: string): string[];
/** `*` matches one segment, `**` the rest; the query string is ignored; percent-encoding is decoded per segment. */
export function pathMatches(pattern: string, path: string): boolean;
export function methodMatches(routeMethod: string | undefined, reqMethod: string): boolean;
export function matchRoute(routes: Route[], method: string, path: string): Route | null;
