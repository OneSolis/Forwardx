import { isIP } from "node:net";
import { assertSafeOutboundHost } from "./ssrf";
import { ipSwitchHookSchema, type IpSwitchHook } from "../shared/hostChinaHealth";
import { enqueueIpSwitchAgentTask, type IpSwitchAgentResult } from "./agentIpSwitchTasks";

export type IpSwitchContext = { hostId: number; serviceId: number; ip: string; incidentId: string };
function template(value: string, context: IpSwitchContext, kind: "url" | "body" | "header") {
  return value.replace(/\{\{(hostId|serviceId|ip|incidentId)\}\}/g, (_, key: keyof IpSwitchContext) => {
    const text = String(context[key]);
    return kind === "url" ? encodeURIComponent(text) : kind === "body" ? JSON.stringify(text).slice(1, -1) : text;
  });
}
/** Only the monitored Agent makes this request, never the panel or a shell. */
export function requestIpSwitch(hook: IpSwitchHook, context: IpSwitchContext): Promise<IpSwitchAgentResult> {
  const request = ipSwitchHookSchema.parse(hook);
  return enqueueIpSwitchAgentTask(context.hostId, {
    taskId: context.incidentId, serviceId: context.serviceId, expectedIp: context.ip,
    request: { ...request, url: template(request.url, context, "url"),
      headers: Object.fromEntries(Object.entries(request.headers).map(([key, value]) => [key, template(value, context, "header")])),
      body: template(request.body, context, "body") },
  });
}
export async function verifyIpSwitchResponse(hook: IpSwitchHook, response: IpSwitchAgentResult, oldIp: string) {
  // HTTP-mode hooks may now be confirmed by the Agent public-IP probe after the
  // request; JSON-mode hooks still require the provider success condition.
  const outcomes = hook.successMode === "http" ? ["accepted", "verified"] : ["verified"];
  if (!outcomes.includes(response.outcome)) throw new Error("provider_success_unconfirmed");
  const ip = response.newIp?.trim();
  if (!ip) {
    if (hook.ipPath) throw new Error("provider_invalid_new_ip");
    return null;
  }
  if (!isIP(ip) || ip === oldIp) throw new Error("provider_invalid_new_ip");
  await assertSafeOutboundHost(ip, { purpose: "新 IP" });
  return ip;
}
