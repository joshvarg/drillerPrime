import os
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii

import angr
import tracer
import claripy
from . import config


l = logging.getLogger("driller.driller")
logging.getLogger('driller.driller').setLevel('DEBUG')
logging.getLogger('angr.exploration_techniques.tracer').setLevel('DEBUG')
#logging.getLogger('angr').setLevel(logging.DEBUG)
class Driller(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input_str, fuzz_bitmap=None, tag=None, redis=None, hooks=None, file_name = None, input_growth=None, depth_limit=None, heuristic=None, argv=None):
        """
        :param binary     : The binary to be traced.
        :param input_str  : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param redis      : redis.Redis instance for coordinating multiple Driller instances.
        :param hooks      : Dictionary of addresses to simprocedures.
        :param file_name  : Name of the file to use as input to the binary
        :param input_growth:The number of bytes to increase the input every iteration (i,e,: 4), defaults to 0.
        :param depth_limit: The depth limit for input drilling, defaults to 1 (Driller's default depth exploration).  
        :param heuristic  : The heuristic type to employ (i.e. :'abort')
        :param argv       : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                            defaults to binary name with no params.
        """

        self.binary      = binary

        # Redis channel identifier.
        self.identifier  = os.path.basename(binary)
        self.input       = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.tag         = tag
        self.redis       = redis
        self.argv = argv or [binary]

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set the name of the file input
        self.file_name = file_name

        # Input growth specifier.
        self.input_growth = int(input_growth) or 0

        # Set depth limit for input drilling
        self.depth_limit = int(depth_limit) or 1
        
        # Set heuristic for symbolic execution
        self.heuristic = heuristic if not heuristic else heuristic.lower()

        # Set of all the generated inputs.
        self._generated = set()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

### DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

        # Don't re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            return -1

        # Write out debug info if desired.
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        list(self._drill_input())

        if self.redis:
            return len(self._generated)
        else:
            return self._generated

    def drill_generator(self):
        """
        A generator interface to the actual drilling.
        """

        # Set up alarm for timeouts.
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i
        
        # Increase input size and initiate drilling
        if self.input_growth:
            self.input = self.input + bytes('0', 'ascii') * int(self.input_growth)
            print('Drilling input: %s' % self.input)
            for w in self._drill_input():
                yield w
        

    def _drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        """

        # initialize the tracer
        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
        p = angr.Project(self.binary)
        # create CFG and obtain starting address for target function
        cfg = p.analyses.CFGFast(force_complete_scan=False)
        diff_fuzz = cfg.functions.function(name='diff_fuzz')
        # initialize callers of target function and obtain address
        target_callers = set() # currently a set to allow multiple callers in the future.
        for caller in cfg.get_all_nodes(addr=diff_fuzz.addr):
            for elm in caller.predecessors:
                target_callers.add(elm.addr) # add address of caller
                
        for addr, proc in self._hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        if p.loader.main_object.os == 'cgc':
            p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

            s = p.factory.entry_state(stdin=angr.SimFileStream, flag_page=r.magic, mode='tracing')
        else:
            s = p.factory.full_init_state(stdin=angr.SimFileStream, mode='tracing')

        s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

        t = angr.exploration_techniques.Tracer(trace=r.trace, crash_addr=r.crash_addr, copy_states=True)
        self._core = angr.exploration_techniques.DrillerCore(trace=r.trace, fuzz_bitmap=self.fuzz_bitmap)

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        self._set_concretizations(simgr.one_active)

        l.debug("Drilling into %r.", self.input)
        l.debug("Input is %r.", self.input)
        
        # perform dry run with tracer until the target function is reached
        simgr.run(until=lambda lsm: len(lsm.active) > 0 and lsm.active[0].addr == list(target_callers)[0])
        # start binary analysis
        while simgr.active and simgr.one_active.globals['trace_idx'] < len(r.trace) - 1:
            simgr.step()

            # Check here to see if a crash has been found.
            if self.redis and self.redis.sismember(self.identifier + '-finished', True):
                return

            if 'diverted' not in simgr.stashes:
                continue

            while simgr.diverted:
                state = simgr.diverted.pop(0)
                l.debug("Found a diverted state, exploring to some extent.")
                w = self._writeout(state.history.bbl_addrs[-1], state)
                if w is not None:
                    # DISABLED!
                    if None and self.depth_limit > 1:
                        depth_lim = self.depth_limit
                        self.depth_limit -= 1
                        self.input = w[1]
                        for new_input in self._drill_input():
                            yield new_input
                        self.depth_limit = depth_lim
                    yield w
                for i in self._symbolic_explorer_stub(state):
                    yield i

### EXPLORER
    def _symbolic_explorer_stub(self, state):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass

        l.debug(
            "[%s] started symbolic exploration at %s.", self.identifier, time.ctime()
        )

        simgr = p.factory.simulation_manager(state, hierarchy=False)
        # Perform iterative deepening upto the depth limit. 
        for i in range(self.depth_limit):
            while len(simgr.active) and accumulated < 1024:
                simgr.step()
                steps += 1
                # Dump all inputs.
                accumulated = steps * (len(simgr.active) + len(simgr.deadended))
            if not len(simgr.active):
                break
            steps = 0
            accumulated = 0

        # Perform heuristic-based iterative deepining for DrillerPrime if a heuristic is given.
        if self.depth_limit > 1 and self.heuristic:
            simgr_copy = simgr.copy(deep=True)
            i = self.depth_limit
            while len(simgr_copy.active) and i > 1:
                simgr.step()
                i -= 1
            simgr_copy.move(
                from_stash="deadended",
                to_stash="heuristic",
                filter_func=lambda s: bytes(self.heuristic, "ascii")
                                      in s.posix.dumps(1).lower(),
            )
            # Move heuristic states and absorb into original sim manager.
            if len(simgr_copy.heuristic) > 0:
                simgr_copy.drop(stash="deadended")
                simgr_copy.drop(stash="active")
                simgr.absorb(simgr_copy)
                simgr.stash(from_stash="heuristic", to_stash="active")
        l.debug(
            "[%s] stopped symbolic exploration at %s.",
            self.identifier,
            time.ctime(),
        )
        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash="deadended", to_stash="active")
        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                if w is not None:
                    yield w
            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass
### UTILS
    @staticmethod
    def _set_concretizations(state):
        if state.project.loader.main_object.os == 'cgc':
            flag_vars = set()
            for b in state.cgc.flag_bytes:
                flag_vars.update(b.variables)

            state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.

        :return: boolean describing whether or not the input generated is redundant.
        """

        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)

        # No redis means no coordination, so no catalogue.
        else:
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # No redis = no catalogue.

    def _writeout(self, prev_addr, state):
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return None

        else:
            self._add_to_catalogue(*key)

        l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            l.debug("Generated: %s", binascii.hexlify(generated))

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            l.debug("Debug log written to %s.", f_name)
            f.write("binary = %r\n" % self.binary
                    + "started = '%s'\n" % time.ctime(self.start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r" % self.fuzz_bitmap)
