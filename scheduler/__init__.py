"""
Hybrid parallel scanning engine.

The scheduler layers a bounded worker pool + job lifecycle ON TOP of the existing
event-driven controller — it does not replace it. Each Job (a target, or a
(target, module) pair) is driven through the SAME ScopeEngine chokepoint, the
SAME shared RateLimiter, the SAME EventBus and output aggregator. Worker count
gates JOB concurrency only; every outbound request still queues on the one
RateLimiter, so a worker count can never multiply the request budget.

Increment 2 ships the job model + lifecycle + persistence; the WorkerPool and
HybridScheduler land in later increments.
"""

from scheduler.engine import HybridScheduler, ModuleSpec, SchedulerReport
from scheduler.jobs import InvalidTransition, Job, JobKind, JobState
from scheduler.pool import WorkerPool
from scheduler.report import build_report_dict, render_report_text

__all__ = [
    "Job", "JobKind", "JobState", "InvalidTransition", "WorkerPool",
    "HybridScheduler", "ModuleSpec", "SchedulerReport",
    "build_report_dict", "render_report_text",
]
