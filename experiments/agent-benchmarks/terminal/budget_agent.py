"""Small Harbor agent: public task instruction -> model -> real environment.exec.

The broker enforces a shared monetary budget. No solution or tests enter prompts.
"""
from __future__ import annotations

import asyncio
import json
import time
import urllib.request
from pathlib import Path

from harbor.agents.base import BaseAgent


class BudgetShellAgent(BaseAgent):
    @staticmethod
    def name() -> str:
        return "observer-budget-shell"

    def version(self) -> str:
        return "1.0"

    async def setup(self, environment) -> None:
        return

    async def run(self, instruction, environment, context) -> None:
        token_path = Path("/opt/agent-benchmarks/private/model-broker-token")
        token = token_path.read_text().strip()
        tools = [{"type": "function", "function": {
            "name": "bash", "description": "Run one shell command inside the task environment.",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}},
                           "required": ["command"], "additionalProperties": False}}},
                 {"type": "function", "function": {
            "name": "finish", "description": "Finish the task when changes have been made.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}}]
        messages = [{"role": "system", "content": "Solve the task in the current Linux environment. Use bash to inspect and edit files, then finish. Never read /solution, /tests or verifier artifacts. Do not access Docker, the host filesystem or host network. Use at most 8 tool rounds. Keep tool output concise. Each response is limited to 2048 tokens: split long source edits into small commands to keep tool-call JSON complete."},
                    {"role": "user", "content": instruction}]
        trajectory, intervals, usage = [], [], {"prompt_tokens": 0, "completion_tokens": 0}
        for index in range(8):
            payload = {"model": "deepseek-flash", "messages": messages, "tools": tools,
                       "max_tokens": 2048, "stream": False}
            def request():
                req = urllib.request.Request("http://10.0.2.2:10090/v1/chat/completions",
                    data=json.dumps(payload).encode(), headers={"Authorization": "Bearer " + token,
                    "Content-Type": "application/json", "X-Benchmark-Task": "terminal-bench/" + str(self.session_id or self.context_id or "unassigned")})
                with urllib.request.urlopen(req, timeout=180) as response:
                    return json.load(response)
            start = time.monotonic_ns()
            result = await asyncio.to_thread(request)
            intervals.append({"kind": "model_request", "index": index,
                              "start_ns": start, "end_ns": time.monotonic_ns()})
            for key in usage:
                usage[key] += result.get("usage", {}).get(key, 0)
            message = result["choices"][0]["message"]
            messages.append(message)
            trajectory.append({"index": index, "assistant": message, "usage": result.get("usage"),
                               "finish_reason": result["choices"][0].get("finish_reason")})
            calls = message.get("tool_calls") or []
            if not calls:
                messages.append({"role": "user", "content": "Call bash or finish."})
                continue
            if len(calls) > 4:
                raise RuntimeError("Model exceeded the declared per-turn tool-call limit")
            finished = False
            for call in calls[:4]:
                name = call["function"]["name"]
                try:
                    args = json.loads(call["function"]["arguments"])
                    if not isinstance(args, dict):
                        raise ValueError("arguments must be a JSON object")
                    if name == "bash" and (not isinstance(args.get("command"), str) or not args["command"].strip()
                                            or len(args["command"].encode()) > 16384):
                        raise ValueError("command must be a nonempty string of at most 16384 bytes")
                except (ValueError, TypeError) as error:
                    messages.append({"role": "tool", "tool_call_id": call["id"],
                        "content": "Rejected malformed tool arguments; no command executed: " + str(error)})
                    intervals.append({"kind": "tool_rejected", "index": index, "tool_call_id": call["id"],
                                      "reason": str(error), "monotonic_ns": time.monotonic_ns()})
                    continue
                if name == "finish":
                    output = "finished"
                    finished = True
                elif name == "bash":
                    command = args["command"]
                    start = time.monotonic_ns()
                    executed = await environment.exec(command=command, timeout_sec=45)
                    output = json.dumps({"stdout": (executed.stdout or "")[:12000],
                        "stderr": (executed.stderr or "")[:4000], "return_code": executed.return_code})
                    intervals.append({"kind": "tool", "index": index, "tool_call_id": call["id"],
                        "command": command, "start_ns": start, "end_ns": time.monotonic_ns(),
                        "return_code": executed.return_code})
                else:
                    output = "Unsupported tool"
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": output})
            # Flush every turn so failed/budget-limited runs retain their executed history.
            self.logs_dir.mkdir(parents=True, exist_ok=True)
            (self.logs_dir / "bounded-agent-trajectory.json").write_text(json.dumps(trajectory, indent=2))
            (self.logs_dir / "tool-intervals.json").write_text(json.dumps(intervals, indent=2))
            context.n_input_tokens = usage["prompt_tokens"]
            context.n_output_tokens = usage["completion_tokens"]
            if finished:
                return
        context.metadata = {"termination": "LOCAL_ROUND_LIMIT", "max_rounds": 8}
