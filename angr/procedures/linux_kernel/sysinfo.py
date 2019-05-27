import angr

from ...sim_type import parse_type

sysinfo_ty = parse_type("""
struct sysinfo {
   long uptime;             /* Seconds since boot */
   unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
   unsigned long totalram;  /* Total usable main memory size */
   unsigned long freeram;   /* Available memory size */
   unsigned long sharedram; /* Amount of shared memory */
   unsigned long bufferram; /* Memory used by buffers */
   unsigned long totalswap; /* Total swap space size */
   unsigned long freeswap;  /* Swap space still available */
   unsigned short procs;    /* Number of current processes */
   unsigned long totalhigh; /* Total high memory size */
   unsigned long freehigh;  /* Available high memory size */
   unsigned int mem_unit;   /* Memory unit size in bytes */
}
""")

class sysinfo(angr.SimProcedure):
    def run(self, info): # pylint: disable=arguments-differ
        value = {
                'uptime': 1234567,
                'loads': [20100,22000,15000],
                'totalram': 1024**2,
                'freeram': 1024**2 // 4,
                'sharedram': 1024**2 // 4,
                'bufferram': 1024**2 // 4,
                'totalswap': 1024**2,
                'freeswap': 1024**2 // 2,
                'procs': 533,
                'totalhigh': 11,
                'freehigh': 12,
                'mem_unit': 13
        }
        sysinfo_ty.with_arch(self.arch).store(self.state, info, value)
