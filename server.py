from concurrent import futures
import logging
import io
from contextlib import redirect_stdout

import timeout_decorator
import sol_pb2,sol_pb2_grpc
import grpc
from grpc_reflection.v1alpha import reflection
from panoramix.loader import Loader
from panoramix.vm import VM
from panoramix.contract import Contract
from panoramix.function import Function
from panoramix.prettify import  pretty_type
from panoramix.whiles import make_whiles

logging.getLogger("panoramix.matcher").setLevel(logging.INFO)
_HOST = 'localhost'
_PORT = '5991'

# Derives from BaseException so it bypasses all the "except Exception" that are
# all around Panoramix code.
class TimeoutInterrupt(BaseException):
    """Thrown when a timeout occurs in the `timeout` context manager."""

    def __init__(self, value="Timed Out"):
        self.value = value

    def __str__(self):
        return repr(self.value)

def decompile(bytecode):
    """Returns decompile content or None."""
    loader = Loader()
    loader.load_binary(bytecode)  # Code is actually hex.
    logging.info("Running light execution to find functions.")

    loader.run(VM(loader, just_fdests=True))
    if len(loader.lines) == 0:
        # No code.
        logging.warning("# No code found for this contract." )

    problems = {}
    functions = {}

    for (hash, fname, target, stack) in loader.func_list:
        """
            hash contains function hash
            fname contains function name
            target contains line# for the given function
        """
        logging.debug("target : "+ str(target) + "-" + loader.lines[target][1])
        try:
            if target > 1 and loader.lines[target][1] == "jumpdest":
                target += 1

            @timeout_decorator(60 * 3, timeout_exception=TimeoutInterrupt, use_signals=False)
            def dec():
                trace = VM(loader).run(target, stack=stack, timeout=60)
                logging.info("Initial decompiled trace")

                trace = make_whiles(trace)
                return trace
            logging.info("xx")
            trace = dec()

            functions[hash] = Function(hash, trace)

        except (Exception, TimeoutInterrupt):
            problems[hash] = fname

    logging.info("Functions decompilation finished, now doing post-processing.")


    contract = Contract(problems=problems, functions=functions,)

    contract.postprocess()

    text_output = io.StringIO()
    with redirect_stdout(text_output):

        """
            Print out decompilation header
        """

        print("# Palkeoramix decompiler. ")

        if len(problems) > 0:
            print("#")
            print("#  I failed with these: ")
            for p in problems.values():
                print(f"#  - {p}")
            print("#  All the rest is below.")
            print("#")

        print()

        """
            Print out constants & storage
        """

        shown_already = set()

        logging.info("len(contract.stor_defs) = "+ str(len(functions.items())) +"a"+ str(len(contract.consts)))
        for func in contract.consts:
            logging.debug("hash: " + func.hash)
            shown_already.add(func.hash)
            func.print()

        if shown_already:
            print()

        if len(contract.stor_defs) > 0:
            print(f"def storage:")

            for s in contract.stor_defs:
                print(pretty_type(s))

            print()

        """
            Print out getters
        """

        for hash, func in functions.items():
            if func.getter is not None:
                shown_already.add(hash)
                print(func.print())

                print()

        """
            Print out regular functions
        """

        func_list = list(contract.functions)
        func_list.sort(
            key=lambda f: f.priority()
        )  # sort func list by length, with some caveats

        if shown_already and any(1 for f in func_list if f.hash not in shown_already):
            # otherwise no irregular functions, so this is not needed :)
            print("#\n#  Regular functions\n#" + "\n")

        for func in func_list:
            hash = func.hash

            if hash not in shown_already:
                shown_already.add(hash)

                print(func.print())

                print()

    """
        Wrap up
    """

    text = text_output.getvalue()
    text_output.close()
    return text

class SolDecompilerServicer(sol_pb2_grpc.SolDecompilerServicer):
    """Provides methods that implement functionality of decompiler server."""

    def Decompile(self, request, context):
        bytecode = request.bytecode
        logging.debug('receive bytecode: ' + bytecode)
        db = decompile(bytecode)
        if db is None:
            return sol_pb2.Response(content="None")
        else:
            return sol_pb2.Response(content=db)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    sol_pb2_grpc.add_SolDecompilerServicer_to_server(
        SolDecompilerServicer(), server)
    reflection.enable_server_reflection([h.service_name() for h in server._state.generic_handlers], server)
    server.add_insecure_port(_HOST + ':' + _PORT)
    server.start()
    logging.info('Server start listen on ' + _HOST + ':' + _PORT)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
    format="%(asctime)s %(filename)s %(levelname)s %(message)s",
    datefmt='%a %d %b %Y %H:%M:%S')
    serve()