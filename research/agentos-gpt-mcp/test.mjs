// Validation: invoke the real SDK MCP transport and enforce a four-tool allowlist.
import { strict as assert } from "node:assert";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { fileURLToPath } from "node:url";

const root=process.env.REA_LAB_EVIDENCE_DIR;
if(!root) throw Error("Set REA_LAB_EVIDENCE_DIR to the curated Evidence directory");
const child=fileURLToPath(new URL("./rea_lab_server.mjs",import.meta.url));
const client=new Client({name:"rea-gpt-lab-test",version:"0.1.0"});
const transport=new StdioClientTransport({
  command:process.execPath,
  args:[child],
  env:{...process.env,REA_LAB_EVIDENCE_DIR:root},
  stderr:"pipe",
});
try {
  await client.connect(transport);
  const tools=await client.listTools();
  const got=tools.tools.map(x=>x.name).sort();
  assert.deepEqual(got,["rea_compare_elf","rea_elf_layout","rea_ghidra_overview","rea_lab_inventory"]);
  assert.equal(tools.tools.every(x=>x.annotations?.readOnlyHint===true),true);
  const inventory=await client.callTool({name:"rea_lab_inventory",arguments:{}});
  assert.equal(inventory.isError??false,false);
  assert.equal(JSON.parse(inventory.content[0].text).os_control,false);
  const systemctl=await client.callTool({name:"rea_elf_layout",arguments:{target:"systemctl"}});
  const layout=JSON.parse(systemctl.content[0].text);
  assert.equal(layout.architecture.machine,"EM_X86_64");
  assert.equal(layout.section_count,32);
  const ghidra=await client.callTool({name:"rea_ghidra_overview",arguments:{target:"systemctl"}});
  assert.equal(JSON.parse(ghidra.content[0].text).procedure_count,1276);
  const comparison=await client.callTool({name:"rea_compare_elf",arguments:{left:"systemctl",right:"systemd-pid1"}});
  assert.equal(JSON.parse(comparison.content[0].text).right.section_count,31);
  const bad=await client.callTool({name:"rea_elf_layout",arguments:{target:"../../etc/passwd"}});
  assert.ok(bad.isError || (bad.content?.[0]?.text??"").includes("error"));
  console.log(JSON.stringify({status:"PASS",tools:got,layout_sections:layout.section_count,ghidra_procedures:1276,unexpected_paths:"DENIED"}));
} finally {
  await client.close();
}
