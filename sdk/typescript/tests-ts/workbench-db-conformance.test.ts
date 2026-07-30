import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";

const scripts = resolve("_bundled_plugin", "scripts");
const temporaryDirectories: string[] = [];
const pythons = ["python3.11", "python3.12", "python3.13", "python3.14"]
  .map((name) => Bun.which(name))
  .filter((path): path is string => path !== null);

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function runPython(
  python: string,
  source: string,
  args: readonly string[] = [],
): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const process = Bun.spawn(
    [python, "-I", "-B", "-c", source, scripts, ...args],
    {
      stderr: "pipe",
      stdout: "pipe",
    },
  );
  const [exitCode, stderr, stdout] = await Promise.all([
    process.exited,
    new Response(process.stderr).text(),
    new Response(process.stdout).text(),
  ]);
  return { exitCode, stderr, stdout };
}

const expectedCommands = `
append-governance-evidence
attach-scan-continuation-thread
begin-deep-scan
begin-diff-resolution
cancel-diff-resolution
cancel-finding-remediation-request
cancel-scan
claim-deep-scan-dedup
claim-finding-remediation-resend
claim-handoff-delivery
commit-deep-scan-dedup
compare-scans
complete-scan
create-workspace
database-info
disable-setup-ui
export-findings
fail-deep-scan
fail-scan
finish-deep-scan
get-deep-scan
get-governance-evidence
get-latest-workspace
get-scan
get-scan-feedback
get-scan-recipe
get-setup-preference
get-workspace
inspect-setup
inspect-target
list-findings
list-global-findings
list-repositories
list-scans
list-unmatched-scan-pairs
list-workspace-scans
mark-finding-remediation-delivered
mark-handoff-delivered
register-cli-scan
release-finding-remediation-claim
release-handoff-delivery
request-finding-remediation
request-finding-remediation-action
save-scan-comparison
save-workspace
set-capability-preflight
set-diff-target
set-finding-remediation
set-finding-triage
start-prompt-only-scan
start-scan
update-progress
upsert-deep-scan-worker
verify-governance-promotion`.trim();

const subprocessSource = `
import argparse,ast,json,os,pathlib,subprocess,sys
scripts=pathlib.Path(sys.argv[1])
sys.path.insert(0,str(scripts))
import workbench_cli,workbench_db
assert "\\n".join(workbench_db.command_names()) == sys.argv[3]
captured=[]
original_parse=argparse.ArgumentParser.parse_args
argparse.ArgumentParser.parse_args=lambda parser: captured.append(parser) or argparse.Namespace()
try: workbench_cli.parse_args("inventory")
finally: argparse.ArgumentParser.parse_args=original_parse
subcommands=next(
    action for action in captured[0]._actions
    if isinstance(action,argparse._SubParsersAction))
assert tuple(sorted(subcommands.choices)) == workbench_db.command_names()
for name in (
    "set_finding_triage","request_finding_remediation",
    "request_finding_remediation_action","claim_finding_remediation_resend",
    "mark_finding_remediation_delivered","release_finding_remediation_claim",
    "set_finding_remediation"):
    assert callable(getattr(workbench_db,name))
for name in (
    "workbench_dispatch.py","workbench_finding_triage.py",
    "workbench_remediation_delivery.py","workbench_remediation_state.py"):
    tree=ast.parse((scripts/name).read_text())
    imports={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)}
    imports.update(
        alias.name for node in ast.walk(tree) if isinstance(node,ast.Import)
        for alias in node.names)
    assert "workbench_db" not in imports
process=subprocess.run(
    [sys.executable,"-I","-B",str(scripts/"workbench_db.py"),
     "inspect-target","--target-path",sys.argv[2]],
    capture_output=True,text=True,check=False,
)
assert process.returncode == 0 and process.stderr == ""
payload=json.loads(process.stdout)
assert process.stdout == json.dumps(payload,allow_nan=False,sort_keys=True)+"\\n"
assert payload["targetPath"] == sys.argv[2]
unknown=subprocess.run(
    [sys.executable,"-I","-B",str(scripts/"workbench_db.py"),"not-a-command"],
    capture_output=True,text=True,check=False,
)
assert unknown.returncode == 2 and unknown.stdout == ""
assert "invalid choice" in unknown.stderr
environment=os.environ.copy()
environment["CODEX_SECURITY_STATE_DIR"]=str(pathlib.Path(sys.argv[2])/"state")
invalid=subprocess.run(
    [sys.executable,"-I","-B",str(scripts/"workbench_db.py"),
     "get-scan","--scan-id","not-a-uuid"],
    capture_output=True,text=True,check=False,env=environment,
)
assert invalid.returncode == 1 and invalid.stdout == ""
assert invalid.stderr == "Codex Security scan not found.\\n"
print(process.stdout,end="")
`;

test("dispatch inventory and subprocess JSON contract hold on supported local Pythons", async () => {
  expect(pythons.length).toBeGreaterThan(0);
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-workbench-parity-")),
  );
  temporaryDirectories.push(root);
  for (const python of pythons) {
    const result = await runPython(python, subprocessSource, [
      root,
      expectedCommands,
    ]);
    expect(result).toMatchObject({ exitCode: 0, stderr: "" });
    expect(JSON.parse(result.stdout)["targetPath"]).toBe(root);
  }
});

const transactionSource = `
import argparse,dataclasses,sqlite3,sys,tempfile
sys.path.insert(0,sys.argv[1])
import workbench_finding_triage as triage
import workbench_remediation_delivery as delivery
import workbench_remediation_state as state

db=sqlite3.connect(":memory:")
db.row_factory=sqlite3.Row
schema="""
CREATE TABLE finding_remediation_attempts (
 request_id TEXT PRIMARY KEY, occurrence_id TEXT, state TEXT, version INTEGER,
 base_revision TEXT, base_content_digest TEXT, patch_path TEXT, patch_digest TEXT,
 applied_content_digest TEXT, pending_action TEXT, pending_action_claimed_at TEXT,
 pending_action_claim_token TEXT, pending_action_delivered_at TEXT,
 summary TEXT, verification_summary TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE finding_triage (
 occurrence_id TEXT PRIMARY KEY, status TEXT, close_reason TEXT, note TEXT, updated_at TEXT);
CREATE TABLE finding_decisions (
 id TEXT, occurrence_id TEXT, status TEXT, close_reason TEXT, note TEXT, created_at TEXT);
"""
db.executescript(schema)
stamp="2026-07-29T12:00:00+00:00"
db.execute("""INSERT INTO finding_remediation_attempts
 (request_id,occurrence_id,state,version,base_revision,base_content_digest,
  pending_action,pending_action_claimed_at,pending_action_claim_token,created_at,updated_at)
 VALUES ('request','finding','requested',1,'rev','digest','generate',?,'owner',?,?)""",
 (stamp,stamp,stamp))
db.commit()
occurrence=lambda connection,value: connection.execute(
 "SELECT 'finding' id, 'scan' scan_id").fetchone()
context=lambda connection,scan_id: {"scanId":scan_id}
delivery_deps=delivery.DeliveryDependencies(
 now=lambda:stamp,require_uuid=lambda value,label:value,
 require_occurrence=occurrence,require_finding_open=lambda connection,value:None,
 stale_claim_before=lambda seconds=300:"2020-01-01T00:00:00+00:00",scan_context=context)
args=argparse.Namespace(occurrence_id="finding",request_id="request",action_token="owner")
before=tuple(db.execute("SELECT * FROM finding_remediation_attempts").fetchone())
assert delivery.claim_finding_remediation_resend(db,args,delivery_deps)["actionToken"]=="owner"
assert tuple(db.execute("SELECT * FROM finding_remediation_attempts").fetchone())==before
args.action_token="intruder"
try: delivery.mark_finding_remediation_delivered(db,args,delivery_deps)
except SystemExit: pass
else: raise AssertionError("ownership rejection missing")
assert tuple(db.execute("SELECT * FROM finding_remediation_attempts").fetchone())==before

triage_deps=triage.TriageDependencies(
 now=lambda:stamp,optional_text=lambda value,maximum=None:value,
 require_close_reason=lambda reason,note:None,require_occurrence=occurrence,
 require_scan=lambda connection,value:None,remediation_claim_is_active=lambda row:True,
 require_remediation_checkout_unchanged=lambda *args,**kwargs:None,scan_context=context)
close=argparse.Namespace(occurrence_id="finding",status="closed",close_reason="wont_fix",note=None)
try: triage.set_finding_triage(db,close,triage_deps)
except SystemExit: pass
else: raise AssertionError("active remediation close rejection missing")
assert db.execute("SELECT COUNT(*) FROM finding_decisions").fetchone()[0]==0
assert db.execute("SELECT COUNT(*) FROM finding_triage").fetchone()[0]==0
assert not db.in_transaction

state_deps=state.StateDependencies(
 now=lambda:stamp,optional_text=lambda value,maximum=None:value,
 require_uuid=lambda value,label:value,require_occurrence=occurrence,
 require_finding_open=lambda connection,value:None,
 require_scan=lambda connection,value:connection.execute("SELECT 'scan' id").fetchone(),
 remediation_claim_is_active=lambda row:True,
 remediation_checkout_snapshot=lambda scan:("rev","digest"),
 require_matching_patch_digest=lambda *args:None,
 require_remediation_checkout_unchanged=lambda *args,**kwargs:None,
 require_remediation_transition=lambda *args:None,
 require_pending_remediation_action=lambda *args:None,
 require_scan_relative_file=lambda scan,value:value,
 require_sha256_digest=lambda value,label:value,
 require_reviewed_patch_applied=lambda *args:"applied",scan_context=context)
request=argparse.Namespace(
 occurrence_id="finding",request_id="new-request",action_token="new-owner")
try: state.request_finding_remediation(db,request,state_deps)
except SystemExit: pass
else: raise AssertionError("active remediation regeneration rejection missing")
assert db.execute("SELECT COUNT(*) FROM finding_remediation_attempts").fetchone()[0]==1
assert not db.in_transaction
def reject_summary(value,maximum=None):
    raise SystemExit("summary-first")
ordered=dataclasses.replace(
    state_deps,optional_text=reject_summary,
    require_occurrence=lambda connection,value:(_ for _ in ()).throw(
        AssertionError("database lookup happened first")))
update=argparse.Namespace(
    occurrence_id="finding",request_id="request",action_token="owner",
    expected_version=1,state="failed",summary="invalid",
    verification_summary=None,patch_path=None,patch_digest=None,base_revision=None)
try: state.set_finding_remediation(db,update,ordered)
except SystemExit as error: assert str(error)=="summary-first"
else: raise AssertionError("input validation order changed")

with tempfile.TemporaryDirectory() as temporary:
    path=temporary+"/contended.sqlite3"
    first=sqlite3.connect(path,timeout=0)
    first.row_factory=sqlite3.Row
    first.executescript(schema)
    first.execute("""INSERT INTO finding_remediation_attempts
     (request_id,occurrence_id,state,version,base_revision,base_content_digest,
      pending_action,pending_action_claimed_at,pending_action_claim_token,created_at,updated_at)
     VALUES ('request','finding','requested',1,'rev','digest','generate',?,'owner',?,?)""",
     (stamp,stamp,stamp))
    first.commit()
    second=sqlite3.connect(path,timeout=0)
    second.row_factory=sqlite3.Row
    first.execute("BEGIN IMMEDIATE")
    args.action_token="contender"
    try: delivery.claim_finding_remediation_resend(second,args,delivery_deps)
    except sqlite3.OperationalError as error: assert "locked" in str(error)
    else: raise AssertionError("concurrent writer was not rejected")
    assert not second.in_transaction
    first.rollback()
    assert first.execute(
        "SELECT pending_action_claim_token FROM finding_remediation_attempts"
    ).fetchone()[0]=="owner"
    first.close()
    second.close()
print("parity-ok")
`;

test("remediation ownership and rollback preserve database snapshots", async () => {
  for (const python of pythons) {
    expect(await runPython(python, transactionSource)).toEqual({
      exitCode: 0,
      stderr: "",
      stdout: "parity-ok\n",
    });
  }
});
