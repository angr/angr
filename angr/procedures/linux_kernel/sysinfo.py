# pylint:disable=missing-class-docstring
from __future__ import annotations
import angr

from ...sim_type import SimStruct, SimTypeLong, SimTypeFixedSizeArray, SimTypeShort, SimTypeInt

# struct sysinfo {
#    long uptime;             /* Seconds since boot */
#    unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
#    unsigned long totalram;  /* Total usable main memory size */
#    unsigned long freeram;   /* Available memory size */
#    unsigned long sharedram; /* Amount of shared memory */
#    unsigned long bufferram; /* Memory used by buffers */
#    unsigned long totalswap; /* Total swap space size */
#    unsigned long freeswap;  /* Swap space still available */
#    unsigned short procs;    /* Number of current processes */
#    unsigned long totalhigh; /* Total high memory size */
#    unsigned long freehigh;  /* Available high memory size */
#    unsigned int mem_unit;   /* Memory unit size in bytes */
# }
sysinfo_ty = SimStruct(
    {
        "uptime": SimTypeLong(signed=True),
        "loads": SimTypeFixedSizeArray(SimTypeLong(signed=False), 3),
        "totalram": SimTypeLong(signed=False),
        "freeram": SimTypeLong(signed=False),
        "sharedram": SimTypeLong(signed=False),
        "bufferram": SimTypeLong(signed=False),
        "totalswap": SimTypeLong(signed=False),
        "freeswap": SimTypeLong(signed=False),
        "procs": SimTypeShort(signed=False),
        "totalhigh": SimTypeLong(signed=False),
        "freehigh": SimTypeLong(signed=False),
        "mem_unit": SimTypeInt(signed=False),
    },
    name="sysinfo",
    pack=False,
    align=None,
)


class sysinfo(angr.SimProcedure):
    def run(self, info):  # pylint: disable=arguments-differ
        value = {
            "uptime": 1234567,
            "loads": [20100, 22000, 15000],
            "totalram": 1024**2,
            "freeram": 1024**2 // 4,
            "sharedram": 1024**2 // 4,
            "bufferram": 1024**2 // 4,
            "totalswap": 1024**2,
            "freeswap": 1024**2 // 2,
            "procs": 533,
            "totalhigh": 11,
            "freehigh": 12,
            "mem_unit": 13,
        }
        sysinfo_ty.with_arch(self.arch).store(self.state, info, value)
        return 0
