# ShieldFlow Autonomous Agentic Loop

## Overview
Continuous improvement system that keeps agents working on meaningful tasks.

## Loop Flow (Every 30 mins)

1. **Check State** - Read `state.json` for current sprint, backlog, in-progress
2. **Discover Work** - Scan `backlog/*.md` and `inbox/*.md` for new tasks
3. **Prioritize** - Score tasks: explicit(40%) + age(25%) + dependencies(20%) + sprint(15%)
4. **Assign** - Match task to available agent based on capability
5. **Execute** - Agent works on task
6. **Update State** - Move task through pipeline, log results
7. **Report** - Output summary to Discord

## State Management

`state.json` tracks:
- Current sprint
- Backlog (pending tasks)
- In-progress (active work)
- Completed (recently done)
- Agent availability
- Cycle history

## Task Format

```markdown
# Task Title

- **ID**: task-001
- **Priority**: P0
- **Agent**: sf-engineering
- **Sprint**: W08
- **Created**: 2026-02-20

## Description
What needs to be done.

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2
```

## Idle Handling
- If no tasks in backlog/inbox → "IDLE: No tasks to assign"
- Log cycle, wait for next trigger

## Active Hours
- Runs 6am-10pm AEST (16 hours)
- 30-minute cycle interval
