import logging
l = logging.getLogger('angr.distributed.worker')

import celery
c = celery.Celery()
c.config_from_object("angr.distributed.celery_config")

from ..project import Project

@c.task
def run_analysis(binary, analysis, args=(), kwargs={}):
    l.info("Loading binary %s", binary)
    p = Project(binary)
    a = getattr(p.analyses, analysis)(*args, **kwargs)
    return a.log, a.errors, a.named_errors
