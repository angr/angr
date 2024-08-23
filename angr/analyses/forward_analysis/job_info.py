from __future__ import annotations
from typing import Generic, TypeVar

JobType = TypeVar("JobType")
JobKey = TypeVar("JobKey")


class JobInfo(Generic[JobType, JobKey]):
    """
    Stores information of each job.
    """

    def __init__(self, key: JobKey, job: JobType):
        self.key = key
        self.jobs = [(job, "")]

        self.narrowing_count = 0  # not used

    def __hash__(self):
        return hash((self.key, *tuple(self.jobs)))

    def __eq__(self, o):
        return type(self) == type(o) and self.key == o.key and self.job == o.job

    def __repr__(self):
        return f"<JobInfo {self.key!s}>"

    @property
    def job(self) -> JobType:
        """
        Get the latest available job.

        :return: The latest available job.
        """

        job, _ = self.jobs[-1]
        return job

    @property
    def merged_jobs(self):
        for job, job_type in self.jobs:
            if job_type == "merged":
                yield job

    @property
    def widened_jobs(self):
        for job, job_type in self.jobs:
            if job_type == "widened":
                yield job

    def add_job(self, job, merged=False, widened=False):
        """
        Appended a new job to this JobInfo node.
        :param job: The new job to append.
        :param bool merged: Whether it is a merged job or not.
        :param bool widened: Whether it is a widened job or not.
        """

        job_type = ""
        if merged:
            job_type = "merged"
        elif widened:
            job_type = "widened"
        self.jobs.append((job, job_type))
