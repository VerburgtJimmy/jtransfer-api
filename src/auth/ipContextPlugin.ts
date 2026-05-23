// Elysia plugin that derives an `ipContext` on every request and
// puts it in scope. Routes read `ctx.ipContext` instead of poking
// at headers themselves — that single chokepoint is what makes the
// CI guardrail (scripts/check-no-raw-ip.ts) able to enforce
// "no raw IP anywhere". See src/utils/ipContext.ts.

import { Elysia } from "elysia";
import { resolveIpContext, type IpContext } from "../utils/ipContext";

export const ipContextPlugin = new Elysia({ name: "ipContext" }).derive(
  { as: "scoped" },
  ({ request }): { ipContext: IpContext } => ({
    ipContext: resolveIpContext(request.headers),
  }),
);
