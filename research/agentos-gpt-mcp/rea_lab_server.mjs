// AgentOS REA Research MCP v0.1 — STDIO-only, read-only Evidence projection.
// This process must run as an unprivileged user with read access ONLY to curated
// immutable Evidence files. Do NOT expose the full 139-tool REA MCP remotely.
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const evidenceDir = process.env.REA_LAB_EVIDENCE_DIR;
if (!evidenceDir || !evidenceDir.startsWith("/")) {
  process.stderr.write("REA_LAB_EVIDENCE_DIR must be an absolute trusted directory\n");
  process.exit(2);
}
const root = resolve(evidenceDir);
const TARGETS = Object.freeze({
  systemctl: Object.freeze({layout:"systemctl.elf.layout.json",deep:"systemctl.elf.ghidra.deep.json"}),
  "systemd-pid1": Object.freeze({layout:"systemd-pid1.elf.layout.json"}),
});

const safeJson = (value) => ({ content: [{ type:"text", text: JSON.stringify(value) }] });
const fail = (kind) => ({ isError:true, content:[{type:"text",text:JSON.stringify({error:kind})}] });

function loadVerified(target, kind) {
  // Target and filename must be from this closed, code-defined set, never
  // caller-submitted filesystem paths.
  const name = TARGETS[target]?.[kind];
  if (!name) throw Error("evidence_not_available");
  const filepath = join(root, name);
  const stat = statSync(filepath, {throwIfNoEntry:false});
  if (!stat?.isFile() || stat.size > 2_000_000 || stat.size < 2) throw Error("evidence_unavailable");
  const data = JSON.parse(readFileSync(filepath,"utf8"));
  if (data?.operation !== (kind === "layout" ? "inspect_binary_layout" : "inspect") ||
      data?.subject?.digest?.sha256 !== data?.normalized_result?.artifact?.sha256 && kind === "layout") {
    throw Error("evidence_identity_mismatch");
  }
  return data;
}
function layout(target) {
  const d = loadVerified(target,"layout");
  const r = d.normalized_result;
  return {
    target,
    sha256:r.artifact.sha256,
    size_bytes:r.artifact.bytes,
    format:r.format,
    architecture:r.architecture,
    image_type:r.image_type,
    section_count:r.sections.length,
    segment_count:r.segments.length,
    symbol_count:r.symbols.length,
    relocation_count:r.relocations.length,
    relocation_inventory_completeness:r.relocation_inventory_completeness,
    dependencies:(r.linkage.needed_libraries??[]).map(x=>x.display).slice(0,64),
    mitigations:r.mitigations,
    provider:d.provider?.id??"unknown",
    limitations:["Static layout only: not runtime health, live permissions, or a complete syscall/call graph."],
  };
}
function ghidraSummary(target) {
  const d=loadVerified(target,"deep");
  const r=d.normalized_result;
  return {target,sha256:d.subject.digest.sha256,provider:d.analysis_profile?.parameters?.upstream_analysis_profile?.provider??d.provider,document:r.document,segment_count:r.segment_count,procedure_count:r.procedure_count,string_count:r.string_count,limitations:["Recognized procedures and strings, not an audited runtime call graph."]};
}
const mcp = new McpServer({name:"agentos-rea-research",version:"0.1.0"},
  {capabilities:{},instructions:"Read-only historical AgentOS REA lab Evidence only. Never infer production OS health or request arbitrary file/process execution."});
const safeAnnotations={readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false};
mcp.registerTool("rea_lab_inventory",
  {title:"REA Research Inventory",description:"List only curated AgentOS Linux binary targets and available verified analyses. No system access.",inputSchema:z.object({}),annotations:safeAnnotations},
  async()=>safeJson({version:"0.1.0",mode:"offline-readonly",target_ids:Object.keys(TARGETS),analysis:["elf_layout","ghidra_overview"],executions:false,filesystem_writes:false,os_control:false}));
mcp.registerTool("rea_elf_layout",
  {title:"Analyze OS Binary ELF Layout",description:"Read REA pwntools results for an exact pre-approved Linux binary; no new processes or paths.",inputSchema:z.object({target:z.enum(["systemctl","systemd-pid1"])}),annotations:safeAnnotations},
  async({target})=>{try{return safeJson(layout(target))}catch{ return fail("evidence_unavailable") }});
mcp.registerTool("rea_ghidra_overview",
  {title:"Ghidra Binary Overview",description:"Read existing REA/Ghidra procedure and string counts for systemctl; no new decompilation.",inputSchema:z.object({target:z.literal("systemctl")}),annotations:safeAnnotations},
  async({target})=>{try{return safeJson(ghidraSummary(target))}catch{return fail("evidence_unavailable")}});
mcp.registerTool("rea_compare_elf",
  {title:"Compare Linux ELF Evidence",description:"Compare two closed-set OS binary layout reports without executing files.",inputSchema:z.object({left:z.enum(["systemctl","systemd-pid1"]),right:z.enum(["systemctl","systemd-pid1"])}),annotations:safeAnnotations},
  async({left,right})=>{try{const a=layout(left),b=layout(right);return safeJson({left:a,right:b,delta:{size_bytes:b.size_bytes-a.size_bytes,sections:b.section_count-a.section_count,relocations:b.relocation_count-a.relocation_count,symbols:b.symbol_count-a.symbol_count},caveat:"Different binaries have different purposes; numeric differences are not quality or security ratings."})}catch{return fail("evidence_unavailable")}});
await mcp.connect(new StdioServerTransport());
