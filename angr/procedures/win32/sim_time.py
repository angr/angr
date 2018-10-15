import angr
import datetime
import time

class GetSystemTimeAsFileTime(angr.SimProcedure):
    timestamp = None
    def run(self, outptr):
        self.instrument()
        self.state.mem[outptr].qword = self.timestamp

    def instrument(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            self.fill_from_timestamp(time.time())
        else:
            self.fill_symbolic()

    def fill_from_timestamp(self, ts):
        self.timestamp = int(ts * 1000 * 1000 / 100)
                    # convert to microseconds, convert to nanoseconds, convert to 100ns intervals

    def fill_symbolic(self):
        self.timestamp = self.state.solver.BVS('SystemTimeAsFileTime', 64, key=('api', 'SystemTimeAsFileTime'))


class GetLocalTime(angr.SimProcedure):
    wYear = None
    wMonth = None
    wDayOfWeek = None
    wDay = None
    wHour = None
    wMinute = None
    wSecond = None
    wMilliseconds = None

    def run(self, outptr):
        self.instrument()
        self.state.mem[outptr].short = self.wYear
        self.state.mem[outptr+2].short = self.wMonth
        self.state.mem[outptr+4].short = self.wDayOfWeek
        self.state.mem[outptr+6].short = self.wDay
        self.state.mem[outptr+8].short = self.wHour
        self.state.mem[outptr+10].short = self.wMinute
        self.state.mem[outptr+12].short = self.wSecond
        self.state.mem[outptr+14].short = self.wMilliseconds

    def instrument(self):
        """
        Override this method, setting the class vars of the same names as the windows SYSTEMTIME structure.
        By default, fills it with appropriately constrained symbolic data, but makes no attempt to make sure that the
        value can make sense semantically, e.g. feb 31 can be represented.

        ...unless the USE_SYSTEM_TIMES state option is present, in which case it will use the system time.

        https://msdn.microsoft.com/en-us/library/windows/desktop/ms724950(v=vs.85).aspx
        """
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            self.fill_from_timestamp(time.time())
        else:
            self.fill_symbolic()

    def fill_symbolic(self):
        """
        Fill the class with constrained symbolic values.
        """
        self.wYear = self.state.solver.BVS('cur_year', 16, key=('api', 'GetLocalTime', 'cur_year'))
        self.wMonth = self.state.solver.BVS('cur_month', 16, key=('api', 'GetLocalTime', 'cur_month'))
        self.wDayOfWeek = self.state.solver.BVS('cur_dayofweek', 16, key=('api', 'GetLocalTime', 'cur_dayofweek'))
        self.wDay = self.state.solver.BVS('cur_day', 16, key=('api', 'GetLocalTime', 'cur_day'))
        self.wHour = self.state.solver.BVS('cur_hour', 16, key=('api', 'GetLocalTime', 'cur_hour'))
        self.wMinute = self.state.solver.BVS('cur_minute', 16, key=('api', 'GetLocalTime', 'cur_minute'))
        self.wSecond = self.state.solver.BVS('cur_second', 16, key=('api', 'GetLocalTime', 'cur_second'))
        self.wMilliseconds = self.state.solver.BVS('cur_millisecond', 16, key=('api', 'GetLocalTime', 'cur_millisecond'))

        self.state.add_constraints(self.wYear >= 1601)
        self.state.add_constraints(self.wYear <= 30827)
        self.state.add_constraints(self.wMonth >= 1)
        self.state.add_constraints(self.wMonth <= 12)
        self.state.add_constraints(self.wDayOfWeek <= 6)
        self.state.add_constraints(self.wDay >= 1)
        self.state.add_constraints(self.wDay <= 31)
        self.state.add_constraints(self.wHour <= 23)
        self.state.add_constraints(self.wMinute <= 59)
        self.state.add_constraints(self.wSecond <= 59)
        self.state.add_constraints(self.wMilliseconds <= 999)

    def fill_from_timestamp(self, ts):
        """
        Fill the class with the appropriate values extracted from the given timestamp.

        :param ts:  A POSIX timestamp.
        """
        dt = datetime.datetime.fromtimestamp(ts)
        self.wYear = dt.year
        self.wMonth = dt.month
        self.wDayOfWeek = dt.isoweekday() % 7 # :/
        self.wDay = dt.day
        self.wHour = dt.hour
        self.wMinute = dt.minute
        self.wSecond = dt.second
        self.wMilliseconds = dt.microsecond // 1000

class QueryPerformanceCounter(angr.SimProcedure):
    def run(self, ptr):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            val = int(time.clock() * 1000000) + 12345678
            self.state.mem[ptr].qword = val
        else:
            self.state.mem[ptr].qword = self.state.solver.BVS('QueryPerformanceCounter_result', 64, key=('api', 'QueryPerformanceCounter'))
        return 1

class GetTickCount(angr.SimProcedure):
    def run(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            return int(time.clock() * 1000) + 12345
        else:
            val = self.state.solver.BVS('GetTickCount_result', 32, key=('api', 'GetTickCount'))
            return val

class GetTickCount64(angr.SimProcedure):
    KEY = ('sim_time', 'GetTickCount')
    def run(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            return int(time.clock() * 1000) + 12345
        else:
            return self.state.solver.BVS('GetTickCount64_result', 64, key=('api', 'GetTickCount64'))
